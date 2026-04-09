// Command ziti-ssh is a full SSH client over OpenZiti with certificate-based
// authentication.
//
// Subcommands:
//
//	ziti-ssh [user@]<target>   — open an interactive SSH session (auto-signs cert)
//	ziti-ssh connect           — same as the root command, explicit form
//	ziti-ssh sign              — obtain/refresh a certificate from ziti-ssh-ca
//	ziti-ssh enroll --jwt <f>  — enroll a Ziti identity from a JWT file
//	ziti-ssh list              — list accessible Ziti services
//	ziti-ssh mfa               — manage MFA TOTP on the Ziti identity
//
// Config file: ~/.config/ziti-ssh/config.yaml (respects XDG_CONFIG_HOME).
// Precedence: CLI flag > config file > built-in default.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openziti/edge-api/rest_model"
	edgeapis "github.com/openziti/sdk-golang/edge-apis"
	ziti "github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/edwardm/ziti-ssh/client"
	"github.com/edwardm/ziti-ssh/config"
)

// ---------------------------------------------------------------------------
// Config file types
// ---------------------------------------------------------------------------

// Config is the structure of ~/.config/ziti-ssh/config.yaml.
type Config struct {
	Identity   string     `yaml:"identity"`
	CAService  string     `yaml:"ca_service"`
	SSHService string     `yaml:"ssh_service"`
	SSHKeyPath string     `yaml:"ssh_key_path"`
	OIDC       OIDCConfig `yaml:"oidc"`
}

// OIDCConfig holds OIDC-related configuration values.
type OIDCConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	CallbackPort string `yaml:"callback_port"`
}

// loadConfig reads the YAML config file at cfgPath. If the file does not exist
// an empty Config is returned without error.
func loadConfig(cfgPath string) (*Config, error) {
	data, err := os.ReadFile(cfgPath)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", cfgPath, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", cfgPath, err)
	}
	return &cfg, nil
}

// defaultConfigPath returns the path to the config file, honouring
// XDG_CONFIG_HOME.
func defaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "ziti-ssh", "config.yaml")
}

// orDefault returns val if non-empty, otherwise fallback.
func orDefault(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Port-forward spec parsing
// ---------------------------------------------------------------------------

// parseLocalForward parses a -L spec of the form:
//
//	[bind:]localport:remotehost:remoteport
//
// A bare 3-part form (localport:remotehost:remoteport) binds to 127.0.0.1.
func parseLocalForward(s string) (client.LocalForwardSpec, error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 3:
		// localport:remotehost:remoteport
		return client.LocalForwardSpec{
			Bind:       "127.0.0.1",
			LocalPort:  parts[0],
			RemoteHost: parts[1],
			RemotePort: parts[2],
		}, nil
	case 4:
		// bind:localport:remotehost:remoteport
		return client.LocalForwardSpec{
			Bind:       parts[0],
			LocalPort:  parts[1],
			RemoteHost: parts[2],
			RemotePort: parts[3],
		}, nil
	default:
		return client.LocalForwardSpec{}, fmt.Errorf(
			"invalid -L spec %q: expected [bind:]localport:remotehost:remoteport", s)
	}
}

// parseRemoteForward parses a -R spec of the form:
//
//	[bind:]remoteport:localhost:localport
func parseRemoteForward(s string) (client.RemoteForwardSpec, error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 3:
		// remoteport:localhost:localport
		return client.RemoteForwardSpec{
			Bind:       "",
			RemotePort: parts[0],
			LocalHost:  parts[1],
			LocalPort:  parts[2],
		}, nil
	case 4:
		// bind:remoteport:localhost:localport
		return client.RemoteForwardSpec{
			Bind:       parts[0],
			RemotePort: parts[1],
			LocalHost:  parts[2],
			LocalPort:  parts[3],
		}, nil
	default:
		return client.RemoteForwardSpec{}, fmt.Errorf(
			"invalid -R spec %q: expected [bind:]remoteport:localhost:localport", s)
	}
}

// parseDynamicForward parses a -D spec of the form:
//
//	[bind:]port
func parseDynamicForward(s string) (client.DynamicForwardSpec, error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		return client.DynamicForwardSpec{Bind: "127.0.0.1", LocalPort: parts[0]}, nil
	case 2:
		return client.DynamicForwardSpec{Bind: parts[0], LocalPort: parts[1]}, nil
	default:
		return client.DynamicForwardSpec{}, fmt.Errorf(
			"invalid -D spec %q: expected [bind:]port", s)
	}
}

// ---------------------------------------------------------------------------
// SSH key helpers
// ---------------------------------------------------------------------------

// candidateKeys is the ordered list of SSH key basenames searched in ~/.ssh/.
var candidateKeys = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// resolveKey returns the absolute path to the SSH private key to use.
// If keyFile is non-empty it is used directly. Otherwise ~/.ssh/ is searched
// in candidateKeys order. If no key exists the user is prompted to generate one.
func resolveKey(keyFile string) (string, error) {
	if keyFile != "" {
		if _, err := os.Stat(keyFile); err != nil {
			return "", fmt.Errorf("key file %q not found: %w", keyFile, err)
		}
		return keyFile, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	sshDir := filepath.Join(home, ".ssh")

	for _, name := range candidateKeys {
		path := filepath.Join(sshDir, name)
		if _, err := os.Stat(path); err == nil {
			slog.Debug("auto-detected SSH key", "path", path)
			return path, nil
		}
	}

	// No key found — offer to generate one.
	fmt.Print("No SSH key found. Generate one now? [y/N] ")
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		answer = ""
	}
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		return "", fmt.Errorf("no SSH key available; provide one with --key or run: ssh-keygen -t ed25519")
	}

	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return "", fmt.Errorf("create ~/.ssh directory: %w", err)
	}
	slog.Info("generating SSH key", "path", keyPath)
	//nolint:gosec // arguments are constant or path-derived; no user-controlled shell injection.
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen failed: %w", err)
	}
	return keyPath, nil
}

// deriveCertPath returns the path where the SSH certificate for privKeyPath
// should live (OpenSSH convention: <key>-cert.pub alongside the private key).
func deriveCertPath(privKeyPath string) string {
	return strings.TrimSuffix(privKeyPath, ".pub") + "-cert.pub"
}

// showCertDetails runs "ssh-keygen -L -f <certPath>" so the user can verify
// the certificate immediately.
func showCertDetails(certPath string) error {
	//nolint:gosec // certPath is derived from a controlled path, not user shell input.
	cmd := exec.Command("ssh-keygen", "-L", "-f", certPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen -L failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sign subcommand logic
// ---------------------------------------------------------------------------

type signParams struct {
	identityFile string
	caService    string
	keyFile      string
	oidc         oidcFlowParams
	zitiTimeout  time.Duration
	verbose      bool // when false, suppress "Certificate written" and showCertDetails
}

// registerZtAPIsPersist subscribes to EventControllerUrlsUpdated on zitiCtx
// and writes the discovered controller URL list back to identityFile on each
// update. Call before Authenticate so that the initial discovery during
// authentication is captured.
func registerZtAPIsPersist(zitiCtx ziti.Context, identityFile string) {
	zitiCtx.Events().On(ziti.EventControllerUrlsUpdated, func(args ...interface{}) {
		if len(args) == 0 {
			return
		}
		urls, ok := args[0].([]*url.URL)
		if !ok {
			return
		}
		strs := make([]string, len(urls))
		for i, u := range urls {
			strs[i] = u.String()
		}
		if err := config.PersistZtAPIs(identityFile, strs); err != nil {
			slog.Warn("failed to persist controller URLs to identity file", "err", err)
		}
	})
}

// runSign obtains a signed SSH certificate from the CA and writes it to disk.
// It is used both by the `sign` subcommand and by runConnect for auto-sign.
func runSign(p signParams) error {
	privKeyPath, err := resolveKey(p.keyFile)
	if err != nil {
		return err
	}

	pubKeyPath := privKeyPath + ".pub"
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("read public key %q: %w", pubKeyPath, err)
	}
	pubKeyLine := strings.TrimSpace(string(pubKeyBytes))
	if pubKeyLine == "" {
		return fmt.Errorf("public key file %q is empty", pubKeyPath)
	}

	slog.Debug("using SSH key", "private", privKeyPath, "public", pubKeyPath)

	zitiCtx, err := ziti.NewContextFromFile(p.identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", p.identityFile, err)
	}
	defer zitiCtx.Close()

	if err := addOIDCCredentials(zitiCtx, p.oidc); err != nil {
		return err
	}

	registerZtAPIsPersist(zitiCtx, p.identityFile)

	if err := config.RunWithTimeout(p.zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	slog.Debug("dialing CA service", "service", p.caService)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), p.zitiTimeout)
	defer dialCancel()
	conn, err := zitiCtx.DialContext(dialCtx, p.caService)
	if err != nil {
		if dialCtx.Err() != nil {
			return config.ZitiTimeoutErr("dial", p.zitiTimeout)
		}
		return fmt.Errorf("dial Ziti service %q: %w", p.caService, err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "%s\n", pubKeyLine); err != nil {
		return fmt.Errorf("send public key to CA: %w", err)
	}

	reader := bufio.NewReader(conn)
	certLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read certificate from CA: %w", err)
	}
	certLine = strings.TrimSpace(certLine)
	if certLine == "" {
		return fmt.Errorf("CA returned no certificate")
	}

	certPath := deriveCertPath(privKeyPath)
	if err := os.WriteFile(certPath, []byte(certLine+"\n"), 0644); err != nil {
		return fmt.Errorf("write certificate to %q: %w", certPath, err)
	}

	if p.verbose {
		fmt.Printf("Certificate written to %s\n", certPath)
		return showCertDetails(certPath)
	}
	return nil
}

// ---------------------------------------------------------------------------
// connect subcommand logic
// ---------------------------------------------------------------------------

// parseTarget splits "[user@]target" into (user, target). If no "@" is
// present the current OS user is returned as the default username.
func parseTarget(arg string) (username, target string, err error) {
	if idx := strings.IndexByte(arg, '@'); idx >= 0 {
		return arg[:idx], arg[idx+1:], nil
	}
	cur, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("determine current user: %w", err)
	}
	return cur.Username, arg, nil
}

// connectParams holds all resolved settings for the connect command.
type connectParams struct {
	identityFile   string
	caService      string
	sshService     string
	service        string // explicit override (--service)
	keyFile        string
	oidc           oidcFlowParams
	zitiTimeout    time.Duration
	target         string // raw "[user@]target" argument
	command        string // optional remote command; empty means interactive shell
	verbose        bool
	noShell        bool                       // -N: do not open a shell, only run forwards
	localForwards  []client.LocalForwardSpec  // -L specs
	remoteForwards []client.RemoteForwardSpec // -R specs
	dynamicProxies []client.DynamicForwardSpec // -D specs
}

// certTimeRemaining parses the certificate at certPath and returns the time
// remaining until it expires, formatted as "XhYm" (e.g. "7h32m"). If the cert
// cannot be read or parsed, the second return value is false.
func certTimeRemaining(certPath string) (string, bool) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", false
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", false
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return "", false
	}
	if cert.ValidBefore == 0 || cert.ValidBefore == ssh.CertTimeInfinity {
		return "", false
	}
	expiry := time.Unix(int64(cert.ValidBefore), 0)
	remaining := time.Until(expiry)
	if remaining <= 0 {
		return "", false
	}
	h := int(remaining.Hours())
	m := int(remaining.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m), true
}

func runConnect(p connectParams) error {
	username, host, err := parseTarget(p.target)
	if err != nil {
		return err
	}

	// Resolve SSH key path before touching the network so we can check cert
	// freshness without authenticating twice.
	privKeyPath, err := resolveKey(p.keyFile)
	if err != nil {
		return err
	}
	certPath := deriveCertPath(privKeyPath)

	if p.verbose {
		fmt.Fprintf(os.Stderr, "%-12s %s\n", "SSH key:", privKeyPath)
	}

	// Auto-sign if the cert is missing or expiring within 5 minutes.
	needsRefresh := client.CertNeedsRefresh(certPath)
	if needsRefresh {
		if p.verbose {
			fmt.Fprintf(os.Stderr, "%-12s missing or expiring — refreshing from %s\n", "Certificate:", p.caService)
		} else {
			fmt.Fprintf(os.Stderr, "certificate missing or expiring soon — obtaining fresh certificate\n")
		}
		if err := runSign(signParams{
			identityFile: p.identityFile,
			caService:    p.caService,
			keyFile:      privKeyPath,
			oidc:         p.oidc,
			zitiTimeout:  p.zitiTimeout,
			verbose:      false,
		}); err != nil {
			return fmt.Errorf("auto-sign: %w", err)
		}
		if p.verbose {
			if remaining, ok := certTimeRemaining(certPath); ok {
				fmt.Fprintf(os.Stderr, "%-12s written to %s (valid %s)\n", "Certificate:", certPath, remaining)
			} else {
				fmt.Fprintf(os.Stderr, "%-12s written to %s\n", "Certificate:", certPath)
			}
		}
	} else if p.verbose {
		if remaining, ok := certTimeRemaining(certPath); ok {
			fmt.Fprintf(os.Stderr, "%-12s valid, expires in %s\n", "Certificate:", remaining)
		} else {
			fmt.Fprintf(os.Stderr, "%-12s valid\n", "Certificate:")
		}
	}

	// Load signer (private key + cert).
	signer, err := client.NewCertSigner(privKeyPath)
	if err != nil {
		return fmt.Errorf("load SSH key: %w", err)
	}

	// Authenticate to Ziti.
	zitiCtx, err := ziti.NewContextFromFile(p.identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", p.identityFile, err)
	}
	defer zitiCtx.Close()

	if err := addOIDCCredentials(zitiCtx, p.oidc); err != nil {
		return err
	}

	registerZtAPIsPersist(zitiCtx, p.identityFile)

	if err := config.RunWithTimeout(p.zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	// Resolve the Ziti service and optional terminator address.
	dialService := p.sshService
	terminatorAddr := host

	if p.service != "" {
		// Explicit --service flag overrides the default service name.
		// The host from [user@]target is still used as the terminator address.
		dialService = p.service
	} else if _, ok := zitiCtx.GetService(host); ok {
		// Target matches a known service name: dial it directly.
		dialService = host
		terminatorAddr = ""
	}

	if p.verbose {
		fmt.Fprintf(os.Stderr, "%-12s %s @ %s\n", "Connecting:", username, host)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), p.zitiTimeout)
	defer dialCancel()

	var netConn net.Conn

	if terminatorAddr != "" {
		slog.Debug("dialing SSH service", "service", dialService, "terminator", terminatorAddr)
		dialOpts := &ziti.DialOptions{
			Identity: terminatorAddr,
		}
		netConn, err = zitiCtx.DialContextWithOptions(dialCtx, dialService, dialOpts)
	} else {
		slog.Debug("dialing SSH service", "service", dialService)
		netConn, err = zitiCtx.DialContext(dialCtx, dialService)
	}
	if err != nil {
		if dialCtx.Err() != nil {
			return config.ZitiTimeoutErr("dial", p.zitiTimeout)
		}
		return fmt.Errorf("dial Ziti service %q: %w", dialService, err)
	}

	hasForwards := len(p.localForwards) > 0 || len(p.remoteForwards) > 0 || len(p.dynamicProxies) > 0

	// When no forwarding is requested, use the fast path that avoids building
	// a full *ssh.Client object (same behaviour as before this feature).
	if !hasForwards {
		if p.command != "" {
			slog.Debug("running remote command", "user", username, "host", host, "command", p.command)
			return client.RunCommand(netConn, username, host, p.command, signer)
		}
		slog.Debug("SSH session starting", "user", username, "host", host)
		return client.RunSession(netConn, username, host, signer)
	}

	// Build an *ssh.Client for forwarding (and optionally a shell session).
	sshClient, err := client.NewSSHClient(netConn, username, host, signer)
	if err != nil {
		return err
	}
	defer sshClient.Close()

	// Context cancelled on SIGINT/SIGTERM so all goroutines shut down cleanly.
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	defer fwdCancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fwdCancel()
		case <-fwdCtx.Done():
		}
	}()

	var wg sync.WaitGroup

	for _, spec := range p.localForwards {
		spec := spec // capture
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := client.RunLocalForward(fwdCtx, sshClient, spec); err != nil {
				slog.Warn("local forward error", "spec", fmt.Sprintf("%+v", spec), "err", err)
			}
		}()
	}

	for _, spec := range p.remoteForwards {
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := client.RunRemoteForward(fwdCtx, sshClient, spec); err != nil {
				slog.Warn("remote forward error", "spec", fmt.Sprintf("%+v", spec), "err", err)
			}
		}()
	}

	for _, spec := range p.dynamicProxies {
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := client.RunDynamicProxy(fwdCtx, sshClient, spec); err != nil {
				slog.Warn("dynamic proxy error", "spec", fmt.Sprintf("%+v", spec), "err", err)
			}
		}()
	}

	if p.noShell {
		// -N: block until signal; no shell opened.
		slog.Debug("port forwards active, waiting for signal (-N)")
		wg.Wait()
		return nil
	}

	// Open a shell session concurrently with the forwards.
	// When the shell exits (or the user disconnects), cancel the forwards.
	sessionErrCh := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer fwdCancel() // cancel forwards when the shell exits
		var sessErr error
		if p.command != "" {
			sessErr = runSSHClientCommand(sshClient, p.command)
		} else {
			sessErr = runSSHClientSession(sshClient)
		}
		sessionErrCh <- sessErr
	}()

	wg.Wait()

	select {
	case err := <-sessionErrCh:
		return err
	default:
		return nil
	}
}

// runSSHClientSession opens an interactive PTY shell on an existing *ssh.Client.
// This mirrors RunSession but accepts an already-constructed client.
func runSSHClientSession(sshClient *ssh.Client) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())

	width, height, err := term.GetSize(stdoutFd)
	if err != nil {
		width, height = 80, 24
	}

	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("set terminal raw mode: %w", err)
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	if err := session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request PTY: %w", err)
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start remote shell: %w", err)
	}

	if err := session.Wait(); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			_ = term.Restore(stdinFd, oldState)
			os.Exit(exitErr.ExitStatus())
		}
		return err
	}
	return nil
}

// runSSHClientCommand runs a non-interactive command on an existing *ssh.Client.
func runSSHClientCommand(sshClient *ssh.Client, command string) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Run(command); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitStatus())
		}
		return fmt.Errorf("run remote command: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// proxy subcommand logic
// ---------------------------------------------------------------------------

// proxyParams holds all resolved settings for the proxy subcommand.
type proxyParams struct {
	identityFile string
	caService    string
	sshService   string
	service      string
	keyFile      string
	oidc         oidcFlowParams
	zitiTimeout  time.Duration
	target       string // raw "[user@]target" argument; user@ portion is ignored
	verbose      bool
}

// runProxy dials the Ziti service for target and copies os.Stdin ↔ conn until
// either side closes. It does NOT establish an SSH session — the raw TCP stream
// is handed to the ssh process that invoked this ProxyCommand.
func runProxy(p proxyParams) error {
	// The user@ portion is irrelevant for proxy mode but we parse it anyway
	// for syntax compatibility (ssh passes "%r@%h" or "%h" from ProxyCommand).
	_, host, err := parseTarget(p.target)
	if err != nil {
		return err
	}

	// Resolve SSH key for cert refresh — same logic as connect.
	privKeyPath, err := resolveKey(p.keyFile)
	if err != nil {
		return err
	}
	certPath := deriveCertPath(privKeyPath)

	// Auto-refresh cert so the outer ssh process finds a valid one.
	if client.CertNeedsRefresh(certPath) {
		if p.verbose {
			fmt.Fprintf(os.Stderr, "%-12s missing or expiring — refreshing from %s\n", "Certificate:", p.caService)
		}
		if err := runSign(signParams{
			identityFile: p.identityFile,
			caService:    p.caService,
			keyFile:      privKeyPath,
			oidc:         p.oidc,
			zitiTimeout:  p.zitiTimeout,
			verbose:      false,
		}); err != nil {
			return fmt.Errorf("proxy: auto-sign: %w", err)
		}
	}

	// Authenticate to Ziti.
	zitiCtx, err := ziti.NewContextFromFile(p.identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", p.identityFile, err)
	}
	defer zitiCtx.Close()

	if err := addOIDCCredentials(zitiCtx, p.oidc); err != nil {
		return err
	}

	registerZtAPIsPersist(zitiCtx, p.identityFile)

	if err := config.RunWithTimeout(p.zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	// Resolve service and terminator the same way connect does.
	dialService := p.sshService
	terminatorAddr := host

	if p.service != "" {
		dialService = p.service
	} else if _, ok := zitiCtx.GetService(host); ok {
		dialService = host
		terminatorAddr = ""
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), p.zitiTimeout)
	defer dialCancel()

	var netConn net.Conn
	if terminatorAddr != "" {
		slog.Debug("proxy: dialing SSH service", "service", dialService, "terminator", terminatorAddr)
		dialOpts := &ziti.DialOptions{Identity: terminatorAddr}
		netConn, err = zitiCtx.DialContextWithOptions(dialCtx, dialService, dialOpts)
	} else {
		slog.Debug("proxy: dialing SSH service", "service", dialService)
		netConn, err = zitiCtx.DialContext(dialCtx, dialService)
	}
	if err != nil {
		if dialCtx.Err() != nil {
			return config.ZitiTimeoutErr("dial", p.zitiTimeout)
		}
		return fmt.Errorf("proxy: dial Ziti service %q: %w", dialService, err)
	}
	defer netConn.Close()

	slog.Debug("proxy: connection established", "host", host)

	// Bridge stdin/stdout ↔ netConn. Two goroutines; we return when either
	// direction closes (whichever happens first, e.g. remote EOF or local EOF).
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(dst, src)
	}
	go cp(netConn, os.Stdin)
	go cp(os.Stdout, netConn)
	<-done
	return nil
}

// ---------------------------------------------------------------------------
// enroll subcommand logic
// ---------------------------------------------------------------------------

func runEnroll(jwtPath, outPath string) error {
	jwtBytes, err := os.ReadFile(jwtPath)
	if err != nil {
		return fmt.Errorf("read JWT from %q: %w", jwtPath, err)
	}
	jwtString := strings.TrimSpace(string(jwtBytes))

	token, jwtToken, err := enroll.ParseToken(jwtString)
	if err != nil {
		return fmt.Errorf("parse enrollment JWT: %w", err)
	}

	keyAlg := ziti.KeyAlgVar("EC")
	enrollFlags := enroll.EnrollmentFlags{
		Token:     token,
		JwtToken:  jwtToken,
		JwtString: jwtString,
		KeyAlg:    keyAlg,
	}

	slog.Info("enrolling Ziti identity", "jwt", jwtPath, "out", outPath)
	cfg, err := enroll.Enroll(enrollFlags)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal identity config: %w", err)
	}
	if err := os.WriteFile(outPath, cfgJSON, 0600); err != nil {
		return fmt.Errorf("write identity file %q: %w", outPath, err)
	}

	slog.Info("identity enrolled", "path", outPath)
	fmt.Printf("Identity enrolled and written to %s\n", outPath)
	return nil
}

// defaultEnrollOut returns the default output path for an enrolled identity:
// ~/.config/ziti-ssh/<basename-of-jwt>.json
func defaultEnrollOut(jwtPath string) string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "ziti-ssh")
	name := strings.TrimSuffix(filepath.Base(jwtPath), filepath.Ext(jwtPath)) + ".json"
	return filepath.Join(dir, name)
}

// ---------------------------------------------------------------------------
// list subcommand logic
// ---------------------------------------------------------------------------

func runList(identityFile string, zitiTimeout time.Duration) error {
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	services, err := zitiCtx.GetServices()
	if err != nil {
		return fmt.Errorf("get services: %w", err)
	}

	if len(services) == 0 {
		fmt.Println("No accessible services found.")
		return nil
	}

	fmt.Printf("%-40s  %s\n", "SERVICE NAME", "PERMISSIONS")
	fmt.Println(strings.Repeat("-", 60))
	for i := range services {
		svc := &services[i]
		name := ""
		if svc.Name != nil {
			name = *svc.Name
		}
		var perms []string
		for _, p := range svc.Permissions {
			perms = append(perms, string(p))
		}
		fmt.Printf("%-40s  %s\n", name, strings.Join(perms, ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// MFA helpers
// ---------------------------------------------------------------------------

func readMFACode(allowEmpty bool) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("MFA TOTP code: ")
		code, _ := reader.ReadString('\n')
		code = strings.TrimSpace(code)
		if code != "" || allowEmpty {
			return code
		}
	}
}

// mfaTotpListener returns a listener function compatible with
// ziti.Events().AddMfaTotpCodeListener.
func mfaTotpListener(_ ziti.Context, _ *rest_model.AuthQueryDetail, response ziti.MfaCodeResponse) {
	for {
		fmt.Println("MFA TOTP required to fully authenticate.")
		code := readMFACode(false)
		if err := response(code); err != nil {
			fmt.Println("error verifying MFA TOTP:", err)
			continue
		}
		break
	}
}

func runMFAEnable(identityFile string, showQR bool, zitiTimeout time.Duration) error {
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	// Register MFA listener before authenticating in case it fires during auth.
	zitiCtx.Events().AddMfaTotpCodeListener(mfaTotpListener)

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	deet, err := zitiCtx.EnrollZitiMfa()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Attempting to enroll for MFA TOTP failed.")
		fmt.Fprintln(os.Stderr, "This identity is likely already enrolled or in the process of being enrolled.")
		fmt.Fprintln(os.Stderr, "Run \"ziti-ssh mfa remove\" to clear the current state, then try again.")
		return fmt.Errorf("enroll MFA: %w", err)
	}

	parsedURL, err := url.Parse(deet.ProvisioningURL)
	if err != nil {
		return fmt.Errorf("parse provisioning URL: %w", err)
	}
	secret := parsedURL.Query().Get("secret")

	fmt.Println()
	fmt.Println("Generate and enter the correct code to continue.")
	fmt.Println("Add this secret to your TOTP generator and verify the code.")
	fmt.Println()
	fmt.Println("  MFA TOTP Secret:", secret)
	if showQR {
		fmt.Printf("  Provisioning URL: %s\n", deet.ProvisioningURL)
		fmt.Println("  (Copy this URL into a TOTP app that accepts provisioning URLs or a QR-code generator.)")
	}
	fmt.Println()

	code := readMFACode(false)
	if err := zitiCtx.VerifyZitiMfa(code); err != nil {
		return fmt.Errorf("verify MFA code: %w", err)
	}

	fmt.Println()
	fmt.Println("Code verified. These are your recovery codes. Save them somewhere safe.")
	fmt.Println("If you lose your TOTP generator, these codes let you re-authenticate.")
	fmt.Println()

	codes := deet.RecoveryCodes
	fmt.Println("┌────────┬────────┬────────┬────────┬────────┐")
	for i := 0; i < len(codes); i += 5 {
		for j := 0; j < 5 && i+j < len(codes); j++ {
			fmt.Printf("│ %6s ", codes[i+j])
		}
		fmt.Println("│")
		if i+5 < len(codes) {
			fmt.Println("├────────┼────────┼────────┼────────┼────────┤")
		}
	}
	fmt.Println("└────────┴────────┴────────┴────────┴────────┘")

	return nil
}

func runMFAVerify(identityFile string, zitiTimeout time.Duration) error {
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	zitiCtx.Events().AddMfaTotpCodeListener(mfaTotpListener)

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	fmt.Println("MFA TOTP verification succeeded.")
	return nil
}

func runMFARemove(identityFile string, zitiTimeout time.Duration) error {
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	done := make(chan error, 1)

	zitiCtx.Events().AddAuthenticationStateFullListener(func(c ziti.Context, _ edgeapis.ApiSession) {
		go func() {
			fmt.Println()
			fmt.Println("If MFA TOTP is enrolled, enter a valid code or recovery code.")
			fmt.Println("Otherwise, enter any value to continue.")
			fmt.Println()
			code := readMFACode(true)
			if err := c.RemoveZitiMfa(code); err != nil {
				done <- fmt.Errorf("remove MFA: %w", err)
				return
			}
			fmt.Println("MFA TOTP removed.")
			done <- nil
		}()
	})

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	return <-done
}

// ---------------------------------------------------------------------------
// main — cobra command tree
// ---------------------------------------------------------------------------

// version is set at build time via -ldflags "-X main.version=<ver>".
var version = "dev"

// connectCmd is declared at package scope so that the root command's RunE can
// reference it after it is assigned in main().
var connectCmd *cobra.Command

func main() {
	var (
		// Persistent flags (available to every subcommand).
		identityFlag    string
		configFlag      string
		zitiTimeoutFlag string
		verbose         bool
		versionFlag     bool

		// Populated by PersistentPreRunE from the config file.
		cfg         *Config
		zitiTimeout time.Duration
	)

	root := &cobra.Command{
		Use:   "ziti-ssh [user@]<target> [-- <command> [args...]]",
		Short: "SSH client over OpenZiti with certificate-based authentication",
		Long: `ziti-ssh is a full SSH client that operates over an OpenZiti network.

When invoked with a target argument it opens an interactive SSH session using
short-lived SSH certificates. Certificates are obtained from the ziti-ssh-ca
service and cached in ~/.ssh/<key>-cert.pub. They are refreshed automatically
when fewer than 5 minutes of validity remain.

If a command is provided after the target (after -- or as trailing arguments),
it is executed non-interactively on the remote host instead of opening a shell.
The remote exit code is propagated to the local process.

Usage:

  ziti-ssh alice@web-server-prod                    # interactive session
  ziti-ssh alice@web-server-prod -- ls -la /tmp     # non-interactive command
  ziti-ssh connect alice@web-server-prod            # same (explicit subcommand)
  ziti-ssh sign                                     # obtain/refresh certificate only
  ziti-ssh enroll --jwt alice.jwt                   # enroll a new Ziti identity
  ziti-ssh list                                     # list accessible services
  ziti-ssh mfa enable                               # enable MFA TOTP`,
		Args: cobra.ArbitraryArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if versionFlag {
				fmt.Printf("ziti-ssh version %s\n", version)
				os.Exit(0)
			}

			// Configure the default slog logger based on the --verbose flag.
			level := slog.LevelWarn
			if verbose {
				level = slog.LevelInfo
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

			cfgPath := configFlag
			if cfgPath == "" {
				cfgPath = defaultConfigPath()
			}
			var err error
			cfg, err = loadConfig(cfgPath)
			if err != nil {
				return err
			}

			zitiTimeoutStr := config.EnvOrFlag(zitiTimeoutFlag, "ZITI_TIMEOUT", "30s")
			zitiTimeout, err = time.ParseDuration(zitiTimeoutStr)
			if err != nil {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT): invalid duration %q: %w", zitiTimeoutStr, err)
			}
			if zitiTimeout <= 0 {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT) must be greater than zero, got %q", zitiTimeoutStr)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			// Delegate to connectCmd so all connect flags are honoured.
			return connectCmd.RunE(cmd, args)
		},
	}

	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Ziti identity file path (or ZITI_IDENTITY)")
	root.PersistentFlags().StringVar(&configFlag, "config", "", "Config file path (default: ~/.config/ziti-ssh/config.yaml)")
	root.PersistentFlags().StringVar(&zitiTimeoutFlag, "ziti-timeout", "", "Timeout for Ziti network operations (or ZITI_TIMEOUT, default: 30s)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose (Info-level) logging")
	root.PersistentFlags().BoolVarP(&versionFlag, "version", "V", false, "Print version and exit")

	// ---------------------------------------------------------------- connect
	var (
		caServiceFlag    string
		sshServiceFlag   string
		serviceFlag      string
		keyFlag          string
		oidcIssuerFlag   string
		noShellFlag      bool
		localFwdFlags    []string
		remoteFwdFlags   []string
		dynamicFwdFlags  []string
	)
	connectCmd = &cobra.Command{
		Use:   "connect [user@]<target> [-- <command> [args...]]",
		Short: "Open an interactive SSH session or run a remote command (the default action)",
		Long: `connect dials the specified target over an OpenZiti network and opens an
interactive SSH session. If a command is provided after the target (separated by
-- or as trailing arguments), it is executed non-interactively on the remote host
instead of opening a shell. The remote exit code is propagated to the local process.

If the local SSH certificate is missing or will expire within 5 minutes it is
automatically refreshed via the ziti-ssh-ca service before connecting.

The target may be given as:
  user@identity-name    — SSH as <user> to the host with Ziti identity <identity-name>
  identity-name         — SSH as the current OS user

If the target exactly matches a Ziti service name it is dialled directly. Otherwise
it is used as a terminator address on the --ssh-service.

Port forwarding flags (-L, -R, -D) may be specified multiple times. Use -N to
forward only without opening a shell.

Examples:
  ziti-ssh connect alice@web-server-prod
  ziti-ssh connect alice@web-server-prod -- ls -la /tmp
  ziti-ssh connect alice@web-server-prod -- systemctl status nginx
  ziti-ssh connect alice@web-server-prod -L 8080:db.internal:5432
  ziti-ssh connect alice@web-server-prod -D 1080
  ziti-ssh connect -N alice@web-server-prod -L 8080:db.internal:5432`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			caService := config.EnvOrFlag(caServiceFlag, "ZITI_CA_SERVICE", orDefault(cfg.CAService, "ssh-ca"))
			sshService := config.EnvOrFlag(sshServiceFlag, "ZITI_SSH_SERVICE", orDefault(cfg.SSHService, "ssh"))
			resolvedKey := keyFlag
			if resolvedKey == "" {
				resolvedKey = cfg.SSHKeyPath
			}
			oidcCallbackPort := cfg.OIDC.CallbackPort
			if oidcCallbackPort == "" {
				oidcCallbackPort = defaultCallbackPort
			}

			// args[0] is always the target; any remaining args form the remote command.
			var remoteCommand string
			if len(args) > 1 {
				remoteCommand = strings.Join(args[1:], " ")
			}

			// Parse forwarding specs.
			var localFwds []client.LocalForwardSpec
			for _, s := range localFwdFlags {
				spec, err := parseLocalForward(s)
				if err != nil {
					return err
				}
				localFwds = append(localFwds, spec)
			}
			var remoteFwds []client.RemoteForwardSpec
			for _, s := range remoteFwdFlags {
				spec, err := parseRemoteForward(s)
				if err != nil {
					return err
				}
				remoteFwds = append(remoteFwds, spec)
			}
			var dynFwds []client.DynamicForwardSpec
			for _, s := range dynamicFwdFlags {
				spec, err := parseDynamicForward(s)
				if err != nil {
					return err
				}
				dynFwds = append(dynFwds, spec)
			}

			return runConnect(connectParams{
				identityFile: identityFile,
				caService:    caService,
				sshService:   sshService,
				service:      serviceFlag,
				keyFile:      resolvedKey,
				oidc: oidcFlowParams{
					Issuer:       orDefault(oidcIssuerFlag, cfg.OIDC.Issuer),
					ClientID:     cfg.OIDC.ClientID,
					ClientSecret: cfg.OIDC.ClientSecret,
					CallbackPort: oidcCallbackPort,
				},
				zitiTimeout:    zitiTimeout,
				target:         args[0],
				command:        remoteCommand,
				verbose:        verbose,
				noShell:        noShellFlag,
				localForwards:  localFwds,
				remoteForwards: remoteFwds,
				dynamicProxies: dynFwds,
			})
		},
	}
	connectCmd.Flags().StringVar(&caServiceFlag, "ca-service", "", "CA service name (or ZITI_CA_SERVICE, default: ssh-ca)")
	connectCmd.Flags().StringVar(&sshServiceFlag, "ssh-service", "", "SSH service name (or ZITI_SSH_SERVICE, default: ssh)")
	connectCmd.Flags().StringVar(&serviceFlag, "service", "", "SSH service name to dial (alias for --ssh-service)")
	connectCmd.Flags().StringVar(&keyFlag, "key", "", "SSH private key path (default: auto-detect from ~/.ssh/)")
	connectCmd.Flags().StringVar(&oidcIssuerFlag, "oidc-issuer", "", "OIDC issuer URL; triggers browser-based OIDC auth before connecting (or set oidc.issuer in config)")
	connectCmd.Flags().BoolVarP(&noShellFlag, "no-shell", "N", false, "Do not open a shell; only forward ports (requires at least one -L, -R, or -D)")
	connectCmd.Flags().StringArrayVarP(&localFwdFlags, "local-forward", "L", nil, "Local port forward: [bind:]localport:remotehost:remoteport (may be repeated)")
	connectCmd.Flags().StringArrayVarP(&remoteFwdFlags, "remote-forward", "R", nil, "Remote port forward: [bind:]remoteport:localhost:localport (may be repeated)")
	connectCmd.Flags().StringArrayVarP(&dynamicFwdFlags, "dynamic", "D", nil, "Dynamic SOCKS5 proxy: [bind:]port (may be repeated)")
	root.AddCommand(connectCmd)

	// ------------------------------------------------------------------ proxy
	var (
		proxyCaServiceFlag  string
		proxySshServiceFlag string
		proxyServiceFlag    string
		proxyKeyFlag        string
		proxyOidcIssuerFlag string
	)
	proxyCmd := &cobra.Command{
		Use:   "proxy [user@]<target>",
		Short: "Dial the target over Ziti and bridge stdio to it (ProxyCommand mode)",
		Long: `proxy dials the target Ziti service and copies os.Stdin/os.Stdout to the raw
TCP connection. No SSH session is established by ziti-ssh itself — the caller's
ssh process handles authentication over the bridged stream.

This is intended for use as a ProxyCommand in ~/.ssh/config:

  Host web-server-prod
      ProxyCommand ziti-ssh proxy %h
      User ziggy

With this in place, standard tools (ssh, git, rsync, VS Code Remote SSH, ansible)
connect through the Ziti overlay transparently without any awareness of ziti-ssh.

The optional user@ prefix is accepted for syntax compatibility with ssh(1) but
the username is not used by ziti-ssh proxy — it only dials the Ziti service.

If the local SSH certificate is missing or will expire within 5 minutes it is
automatically refreshed before dialling, so that the ssh process that invokes
ProxyCommand will find a valid cert in ~/.ssh/<key>-cert.pub.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			caService := config.EnvOrFlag(proxyCaServiceFlag, "ZITI_CA_SERVICE", orDefault(cfg.CAService, "ssh-ca"))
			sshService := config.EnvOrFlag(proxySshServiceFlag, "ZITI_SSH_SERVICE", orDefault(cfg.SSHService, "ssh"))
			resolvedKey := proxyKeyFlag
			if resolvedKey == "" {
				resolvedKey = cfg.SSHKeyPath
			}
			proxyCallbackPort := cfg.OIDC.CallbackPort
			if proxyCallbackPort == "" {
				proxyCallbackPort = defaultCallbackPort
			}
			return runProxy(proxyParams{
				identityFile: identityFile,
				caService:    caService,
				sshService:   sshService,
				service:      proxyServiceFlag,
				keyFile:      resolvedKey,
				oidc: oidcFlowParams{
					Issuer:       orDefault(proxyOidcIssuerFlag, cfg.OIDC.Issuer),
					ClientID:     cfg.OIDC.ClientID,
					ClientSecret: cfg.OIDC.ClientSecret,
					CallbackPort: proxyCallbackPort,
				},
				zitiTimeout: zitiTimeout,
				target:      args[0],
				verbose:     verbose,
			})
		},
	}
	proxyCmd.Flags().StringVar(&proxyCaServiceFlag, "ca-service", "", "CA service name (or ZITI_CA_SERVICE, default: ssh-ca)")
	proxyCmd.Flags().StringVar(&proxySshServiceFlag, "ssh-service", "", "SSH service name (or ZITI_SSH_SERVICE, default: ssh)")
	proxyCmd.Flags().StringVar(&proxyServiceFlag, "service", "", "SSH service name to dial (alias for --ssh-service)")
	proxyCmd.Flags().StringVar(&proxyKeyFlag, "key", "", "SSH private key path (default: auto-detect from ~/.ssh/)")
	proxyCmd.Flags().StringVar(&proxyOidcIssuerFlag, "oidc-issuer", "", "OIDC issuer URL; triggers browser-based OIDC auth before dialling (or set oidc.issuer in config)")
	root.AddCommand(proxyCmd)

	// ------------------------------------------------------------------ sign
	var (
		signCaServiceFlag string
		signKeyFlag       string
	)
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Obtain or refresh an SSH certificate from ziti-ssh-ca",
		Long: `sign connects to the ziti-ssh-ca service over the Ziti network, sends your
SSH public key, and writes the signed certificate to ~/.ssh/<key>-cert.pub.

The certificate details are printed via ssh-keygen -L immediately after writing
so you can verify the principal, validity window, and extensions.

Certificates expire after the TTL configured on the CA (default: 8 h). Run
"ziti-ssh sign" again to renew before the old one expires.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			caService := config.EnvOrFlag(signCaServiceFlag, "ZITI_CA_SERVICE", orDefault(cfg.CAService, "ssh-ca"))
			resolvedKey := signKeyFlag
			if resolvedKey == "" {
				resolvedKey = cfg.SSHKeyPath
			}
			signCallbackPort := cfg.OIDC.CallbackPort
			if signCallbackPort == "" {
				signCallbackPort = defaultCallbackPort
			}
			return runSign(signParams{
				identityFile: identityFile,
				caService:    caService,
				keyFile:      resolvedKey,
				oidc: oidcFlowParams{
					Issuer:       cfg.OIDC.Issuer,
					ClientID:     cfg.OIDC.ClientID,
					ClientSecret: cfg.OIDC.ClientSecret,
					CallbackPort: signCallbackPort,
				},
				zitiTimeout: zitiTimeout,
				verbose:     true,
			})
		},
	}
	signCmd.Flags().StringVar(&signCaServiceFlag, "ca-service", "", "CA service name (or ZITI_CA_SERVICE, default: ssh-ca)")
	signCmd.Flags().StringVar(&signKeyFlag, "key", "", "SSH private key path (default: auto-detect from ~/.ssh/)")
	root.AddCommand(signCmd)

	// ---------------------------------------------------------------- enroll
	var (
		enrollJWTFlag string
		enrollOutFlag string
	)
	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a Ziti identity from a JWT file",
		Long: `enroll reads the one-time enrollment JWT produced by "ziti edge create identity"
and produces an enrolled identity JSON file that can be used with --identity.

The output path defaults to ~/.config/ziti-ssh/<jwt-basename>.json.

Example:
  ziti-ssh enroll --jwt alice.jwt
  ziti-ssh enroll --jwt alice.jwt --out ~/.config/ziti-ssh/alice.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outPath := enrollOutFlag
			if outPath == "" {
				outPath = defaultEnrollOut(enrollJWTFlag)
			}
			return runEnroll(enrollJWTFlag, outPath)
		},
	}
	enrollCmd.Flags().StringVar(&enrollJWTFlag, "jwt", "", "Path to enrollment JWT file (required)")
	enrollCmd.Flags().StringVar(&enrollOutFlag, "out", "", "Output path for identity JSON (default: ~/.config/ziti-ssh/<name>.json)")
	_ = enrollCmd.MarkFlagRequired("jwt")
	root.AddCommand(enrollCmd)

	// ------------------------------------------------------------------ list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List Ziti services accessible to this identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			return runList(identityFile, zitiTimeout)
		},
	}
	root.AddCommand(listCmd)

	// ------------------------------------------------------------------- mfa
	mfaCmd := &cobra.Command{
		Use:   "mfa",
		Short: "Manage MFA TOTP for the Ziti identity",
	}

	var mfaShowQR bool
	mfaEnableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable MFA TOTP for the Ziti identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			return runMFAEnable(identityFile, mfaShowQR, zitiTimeout)
		},
	}
	mfaEnableCmd.Flags().BoolVarP(&mfaShowQR, "qr-code", "q", false, "Print the provisioning URL (paste into a TOTP app or QR-code generator)")

	mfaVerifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify MFA TOTP authentication (smoke-test)",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			return runMFAVerify(identityFile, zitiTimeout)
		},
	}

	mfaRemoveCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove MFA TOTP from the Ziti identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", cfg.Identity)
			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			return runMFARemove(identityFile, zitiTimeout)
		},
	}

	mfaCmd.AddCommand(mfaEnableCmd, mfaVerifyCmd, mfaRemoveCmd)
	root.AddCommand(mfaCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ziti-ssh version %s\n", version)
		},
	}
	root.AddCommand(versionCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// Compile-time assertion: confirm the time package is referenced.
var _ = time.Now
