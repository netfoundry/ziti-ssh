// Command ziti-ssh-host manages an SSH host's integration with an OpenZiti network.
//
// Subcommands:
//
//	enroll --jwt <path>   Enroll this host as a Ziti identity, configure sshd to
//	                      trust the CA, and reload sshd.
//
//	run                   Listen on the Ziti ssh service and proxy connections to
//	                      the local sshd on 127.0.0.1:22.
//
//	inspect               Show the resolved ziti-ssh-host.v1 config for one or
//	                      more services. Exits without opening any listeners.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/openziti/edge-api/rest_model"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	ziti "github.com/openziti/sdk-golang/ziti"
	zitiEdge "github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/enroll"

	"github.com/edwardm/ziti-ssh/ca"
	"github.com/edwardm/ziti-ssh/config"
	"github.com/edwardm/ziti-ssh/host"
)

const (
	defaultIdentityFile  = "/etc/ziti-ssh-host/identity.json"
	defaultCaService     = "ssh-ca"
	defaultSSHService    = "ssh"
	defaultSSHTarget     = "127.0.0.1:22"
	sshdConfFile         = "/etc/ssh/sshd_config.d/ziti-ssh.conf"
	sshdCAPubKeyFile     = "/etc/ssh/ziti_ca.pub"
	userManagerStateFile = "/var/lib/ziti-ssh-host/managed-users"

	// zitiSSHHostConfigType is the Ziti service config type that carries
	// per-identity Linux permissions for a service.
	zitiSSHHostConfigType = "ziti-ssh-host.v1"
)

// version is set at build time via -ldflags "-X main.version=<ver>".
var version = "dev"

func main() {
	var (
		identityFlag    string
		caServiceFlag   string
		sshServicesFlag []string
		zitiTimeoutFlag string
		versionFlag     bool
	)

	root := &cobra.Command{
		Use:   "ziti-ssh-host",
		Short: "SSH host daemon for OpenZiti networks",
		RunE: func(cmd *cobra.Command, args []string) error {
			if versionFlag {
				fmt.Printf("ziti-ssh-host version %s\n", version)
				return nil
			}
			return cmd.Help()
		},
	}

	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Path to Ziti identity file (or ZITI_IDENTITY, default: "+defaultIdentityFile+")")
	root.PersistentFlags().StringVar(&caServiceFlag, "ca-service", "", "Ziti service name for the SSH CA (or ZITI_CA_SERVICE, default: "+defaultCaService+")")
	// --ssh-service now accepts multiple values; a single value still works.
	root.PersistentFlags().StringArrayVar(&sshServicesFlag, "ssh-service", nil, "Ziti service name for SSH (repeatable; or ZITI_SSH_SERVICE comma-separated, default: "+defaultSSHService+")")
	root.PersistentFlags().StringVar(&zitiTimeoutFlag, "ziti-timeout", "", "Timeout for Ziti network operations (or ZITI_TIMEOUT, default: 30s)")
	root.PersistentFlags().BoolVarP(&versionFlag, "version", "V", false, "Print version and exit")

	// ------------------------------------------------------------------ enroll
	var jwtPath string
	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this host, configure sshd, and reload sshd",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", defaultIdentityFile)
			caService := config.EnvOrFlag(caServiceFlag, "ZITI_CA_SERVICE", defaultCaService)
			return runEnroll(jwtPath, identityFile, caService)
		},
	}
	enrollCmd.Flags().StringVar(&jwtPath, "jwt", "", "Path to enrollment JWT file (required)")
	_ = enrollCmd.MarkFlagRequired("jwt")

	// --------------------------------------------------------------------- run
	var modeFlag string
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Listen on the Ziti ssh service and proxy to local sshd",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", defaultIdentityFile)
			sshServices := resolveSshServices(sshServicesFlag)
			mode := config.EnvOrFlag(modeFlag, "ZITI_SSH_MODE", "shared")
			if mode != "shared" && mode != "per-identity" {
				return fmt.Errorf("--mode must be \"shared\" or \"per-identity\", got %q", mode)
			}
			zitiTimeoutStr := config.EnvOrFlag(zitiTimeoutFlag, "ZITI_TIMEOUT", "30s")
			zitiTimeout, err := time.ParseDuration(zitiTimeoutStr)
			if err != nil {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT): invalid duration %q: %w", zitiTimeoutStr, err)
			}
			if zitiTimeout <= 0 {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT) must be greater than zero, got %q", zitiTimeoutStr)
			}
			return runProxy(identityFile, sshServices, mode, zitiTimeout)
		},
	}
	runCmd.Flags().StringVar(&modeFlag, "mode", "", "Principal mode: \"shared\" (default) or \"per-identity\" (or set ZITI_SSH_MODE)")

	// ----------------------------------------------------------------- inspect
	var inspectServicesFlag []string
	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show the resolved ziti-ssh-host.v1 config for one or more services",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", defaultIdentityFile)
			zitiTimeoutStr := config.EnvOrFlag(zitiTimeoutFlag, "ZITI_TIMEOUT", "30s")
			zitiTimeout, err := time.ParseDuration(zitiTimeoutStr)
			if err != nil {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT): invalid duration %q: %w", zitiTimeoutStr, err)
			}
			if zitiTimeout <= 0 {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT) must be greater than zero, got %q", zitiTimeoutStr)
			}
			if len(inspectServicesFlag) == 0 {
				return fmt.Errorf("at least one --service must be specified")
			}
			return runInspect(identityFile, inspectServicesFlag, zitiTimeout)
		},
	}
	inspectCmd.Flags().StringArrayVar(&inspectServicesFlag, "service", nil, "Service name to inspect (repeatable)")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ziti-ssh-host version %s\n", version)
		},
	}

	root.AddCommand(enrollCmd, runCmd, inspectCmd, versionCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// resolveSshServices returns the list of SSH service names to bind to.
// Precedence: --ssh-service flags > ZITI_SSH_SERVICE env (comma-separated) > ["ssh"].
func resolveSshServices(flagValues []string) []string {
	if len(flagValues) > 0 {
		return flagValues
	}
	if env := os.Getenv("ZITI_SSH_SERVICE"); env != "" {
		var result []string
		for _, s := range strings.Split(env, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				result = append(result, s)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return []string{defaultSSHService}
}

// parseGlobalGroups reads ZITI_SSH_GROUPS from the environment and returns a
// slice of group names (whitespace-trimmed, empty strings skipped).
func parseGlobalGroups() []string {
	raw := os.Getenv("ZITI_SSH_GROUPS")
	if raw == "" {
		return nil
	}
	var groups []string
	for _, g := range strings.Split(raw, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

// newZitiContextWithConfigTypes loads a Ziti context from identityFile and
// appends configType to the context's declared config types before the first
// Authenticate call. This is required for the SDK to deliver service config
// data of that type.
func newZitiContextWithConfigTypes(identityFile string, configTypes ...string) (ziti.Context, error) {
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("load Ziti config from %q: %w", identityFile, err)
	}
	cfg.ConfigTypes = append(cfg.ConfigTypes, configTypes...)
	return ziti.NewContext(cfg)
}

// runEnroll enrolls this host with the Ziti network (using jwtPath), extracts
// the intermediate CA public key from the enrollment response, writes the sshd
// configuration, and reloads sshd.
//
// The caService parameter is retained in the function signature for API
// compatibility but is no longer used; the CA public key is derived directly
// from the enrolled certificate chain rather than fetched over the network.
func runEnroll(jwtPath, identityFile, _ string) error {
	// 1. Read and parse the JWT.
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
	flags := enroll.EnrollmentFlags{
		Token:     token,
		JwtToken:  jwtToken,
		JwtString: jwtString,
		KeyAlg:    keyAlg,
	}

	slog.Info("enrolling Ziti identity", "identity_file", identityFile)

	// 2. Perform enrollment. The returned *ziti.Config contains the full
	// certificate chain in cfg.ID.CA (PEM-encoded, "pem:" prefix).
	cfg, err := enroll.Enroll(flags)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	// 3. Write identity file (create parent dir with 0700).
	if err := os.MkdirAll(filepath.Dir(identityFile), 0700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal identity config: %w", err)
	}
	if err := os.WriteFile(identityFile, cfgJSON, 0600); err != nil {
		return fmt.Errorf("write identity file %q: %w", identityFile, err)
	}
	slog.Info("identity enrolled", "path", identityFile)

	// 4. Extract the intermediate CA public key from the enrollment response.
	// This avoids any network call to the ssh-ca service during enrollment.
	caPubBytes, err := intermediateCAPublicKey(cfg)
	if err != nil {
		return fmt.Errorf("extract intermediate CA public key: %w", err)
	}

	// 5. Write sshd configuration.
	if err := host.WriteSSHConfig(caPubBytes, sshdConfFile, sshdCAPubKeyFile); err != nil {
		return fmt.Errorf("write sshd config: %w", err)
	}

	// 6. Reload sshd.
	if err := host.ReloadSSHD(); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}

	slog.Info("enrollment complete")
	return nil
}

// intermediateCAPublicKey extracts the intermediate CA public key from the
// enrollment result and returns it in authorized_keys format, ready to write
// to TrustedUserCAKeys.
//
// The PKI hierarchy is:
//
//	Root CA (offline)
//	  └── Controller Intermediate CA  ← this key signs Ziti identities
//	        └── Ziti Identity Cert    ← issued to this host
//
// After enrollment, cfg.ID.CA contains the PEM-encoded certificate chain
// returned by the controller (root CA + intermediate CA). cfg.ID.Cert contains
// the identity cert for this host. The intermediate CA is identified as the
// cert in the chain whose Subject matches the issuer of the identity cert.
//
// sshd's TrustedUserCAKeys must contain the intermediate CA public key because
// that is the key that signed the Ziti identity certificates used as SSH
// principals. The root CA key never appears in TrustedUserCAKeys.
func intermediateCAPublicKey(cfg *ziti.Config) ([]byte, error) {
	// cfg.ID.CA is stored as "pem:<PEM data>"; strip the scheme prefix.
	caPEM := strings.TrimPrefix(cfg.ID.CA, "pem:")
	if caPEM == "" {
		return nil, fmt.Errorf("enrollment result contains no CA certificate chain (cfg.ID.CA is empty)")
	}

	// cfg.ID.Cert is stored as "pem:<PEM data>"; strip the scheme prefix.
	certPEM := strings.TrimPrefix(cfg.ID.Cert, "pem:")
	if certPEM == "" {
		return nil, fmt.Errorf("enrollment result contains no identity certificate (cfg.ID.Cert is empty)")
	}

	// Parse the identity certificate to get its Issuer.
	identityCert, err := parseSingleCert([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("parse identity certificate: %w", err)
	}

	// Parse all CA certificates from the chain.
	caCerts, err := parseAllCerts([]byte(caPEM))
	if err != nil {
		return nil, fmt.Errorf("parse CA chain: %w", err)
	}
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("CA chain is empty")
	}

	// The intermediate CA is the cert in the chain whose Subject matches the
	// Issuer of the identity cert. This is the controller's intermediate CA —
	// the key that signs Ziti identity certificates (and therefore the key that
	// ziti-ssh-ca uses to sign SSH certificates).
	for _, c := range caCerts {
		if c.Subject.String() == identityCert.Issuer.String() {
			sshPub, err := ssh.NewPublicKey(c.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("convert intermediate CA public key to SSH format: %w", err)
			}
			slog.Info("extracted intermediate CA public key from enrollment chain",
				"subject", c.Subject.String())
			return ssh.MarshalAuthorizedKey(sshPub), nil
		}
	}

	return nil, fmt.Errorf("intermediate CA not found in chain: no cert in CA chain has Subject matching identity cert Issuer %q",
		identityCert.Issuer.String())
}

// parseSingleCert decodes the first PEM CERTIFICATE block in data and returns
// the parsed x509.Certificate.
func parseSingleCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate: %w", err)
	}
	return cert, nil
}

// parseAllCerts decodes all PEM CERTIFICATE blocks in data and returns the
// parsed certificates.
func parseAllCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// serviceState holds the mutable per-service state that may be hot-reloaded
// when the Ziti controller pushes a service-changed event.
type serviceState struct {
	mu     sync.RWMutex
	config *host.PermissionsConfig // nil if no ziti-ssh-host.v1 config is attached
}

func (s *serviceState) get() *host.PermissionsConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *serviceState) set(pc *host.PermissionsConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = pc
}

// loadPermissionsConfig fetches and parses the ziti-ssh-host.v1 config from
// serviceName via zitiCtx. Returns nil when no such config is attached.
func loadPermissionsConfig(zitiCtx ziti.Context, serviceName string) (*host.PermissionsConfig, error) {
	svc, ok := zitiCtx.GetService(serviceName)
	if !ok {
		return nil, fmt.Errorf("service %q not found (check bind policy)", serviceName)
	}

	// ParseServiceConfig populates target from the service's config map.
	// We need to decode the raw JSON map into our struct. The SDK uses
	// mapstructure under the hood. We define a wire-format struct that matches
	// the JSON schema exactly.
	type wirePermEntry struct {
		Groups      []string `mapstructure:"groups"`
		SudoersRule string   `mapstructure:"sudoers_rule"`
	}
	type wireConfig struct {
		Permissions map[string]wirePermEntry `mapstructure:"permissions"`
	}

	var wire wireConfig
	found, err := zitiEdge.ParseServiceConfig(svc, zitiSSHHostConfigType, &wire)
	if err != nil {
		return nil, fmt.Errorf("parse %s config for service %q: %w", zitiSSHHostConfigType, serviceName, err)
	}
	if !found {
		slog.Debug("no ziti-ssh-host.v1 config attached to service", "service", serviceName)
		return nil, nil
	}

	pc := &host.PermissionsConfig{
		Permissions: make(map[string]host.IdentityPermissions, len(wire.Permissions)),
	}
	for identity, entry := range wire.Permissions {
		pc.Permissions[identity] = host.IdentityPermissions{
			Groups:      entry.Groups,
			SudoersRule: entry.SudoersRule,
		}
	}
	slog.Info("loaded ziti-ssh-host.v1 config", "service", serviceName, "identities", len(pc.Permissions))
	return pc, nil
}

// runProxy initializes a Ziti context, listens on each ssh service using the
// host's identity name as the terminator address, and proxies all connections
// to the local sshd.
//
// In "per-identity" mode a UserManager is created, orphan cleanup is run at
// startup, and ProxyHooks are wired to create/delete Linux users as sessions
// open and close. Each service gets its own ProxyHooks that resolve permissions
// from that service's ziti-ssh-host.v1 config.
func runProxy(identityFile string, sshServices []string, mode string, zitiTimeout time.Duration) error {
	// Use NewConfigFromFile + NewContext so we can inject ConfigTypes before
	// the first Authenticate call.
	zitiCtx, err := newZitiContextWithConfigTypes(identityFile, zitiSSHHostConfigType)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	// Global fallback permissions from environment variables.
	globalSudoersRule := os.Getenv("ZITI_SUDOERS_RULE")
	globalGroups := parseGlobalGroups()
	cleanupOnDisconnect := os.Getenv("ZITI_USER_CLEANUP") != "false"

	listenOpts := &ziti.ListenOptions{
		BindUsingEdgeIdentity: true,
	}

	// Open a listener for each service and load its permissions config.
	type serviceEntry struct {
		name     string
		listener zitiEdge.Listener
		state    *serviceState
	}

	entries := make([]serviceEntry, 0, len(sshServices))
	for _, svcName := range sshServices {
		svcName := svcName // capture
		var listener zitiEdge.Listener
		if err := config.RunWithTimeout(zitiTimeout, "listen on "+svcName, func() error {
			var listenErr error
			listener, listenErr = zitiCtx.ListenWithOptions(svcName, listenOpts)
			if listenErr != nil {
				return fmt.Errorf("listen on Ziti service %q: %w", svcName, listenErr)
			}
			return nil
		}); err != nil {
			// Close already-opened listeners before returning.
			for _, e := range entries {
				e.listener.Close()
			}
			return err
		}

		state := &serviceState{}
		if mode == "per-identity" {
			pc, err := loadPermissionsConfig(zitiCtx, svcName)
			if err != nil {
				slog.Warn("could not load permissions config, using global fallbacks only",
					"service", svcName, "err", err)
			}
			state.set(pc)
		}

		entries = append(entries, serviceEntry{
			name:     svcName,
			listener: listener,
			state:    state,
		})
	}

	// Defer close on all listeners.
	defer func() {
		for _, e := range entries {
			e.listener.Close()
		}
	}()

	for _, e := range entries {
		slog.Info("proxying", "service", e.name, "target", defaultSSHTarget, "mode", mode)
	}

	// Notify systemd that the service is ready to accept connections.
	// This is a no-op when not running under systemd (NOTIFY_SOCKET is unset).
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		slog.Debug("sd_notify READY failed (not running under systemd?)", "err", err)
	}

	var (
		mgr    *host.UserManager
		wg     sync.WaitGroup // tracks Proxy goroutines (one per listener)
		connWg sync.WaitGroup // tracks individual in-flight connections
	)

	if mode == "per-identity" {
		mgr = host.NewUserManager(userManagerStateFile, cleanupOnDisconnect)

		slog.Info("running orphan user cleanup")
		if err := mgr.CleanupOrphans(); err != nil {
			// Log but do not abort — a cleanup failure is not fatal to startup.
			slog.Error("orphan cleanup failed", "err", err)
		}
	}

	// Subscribe to service-changed events so we can hot-reload permissions.
	if mode == "per-identity" {
		// Build a lookup map from service name to its state for the listener.
		stateByName := make(map[string]*serviceState, len(entries))
		for _, e := range entries {
			stateByName[e.name] = e.state
		}

		removeListener := zitiCtx.Events().AddServiceChangedListener(func(_ ziti.Context, svc *rest_model.ServiceDetail) {
			if svc == nil || svc.Name == nil {
				return
			}
			svcName := *svc.Name
			st, ok := stateByName[svcName]
			if !ok {
				return // not a service we care about
			}
			slog.Info("service-changed event received, reloading permissions config", "service", svcName)
			pc, err := loadPermissionsConfig(zitiCtx, svcName)
			if err != nil {
				slog.Error("failed to reload permissions config", "service", svcName, "err", err)
				return
			}
			st.set(pc)
			slog.Info("permissions config reloaded", "service", svcName)
		})
		defer removeListener()
	}

	// Start a proxy goroutine for each service listener.
	for _, e := range entries {
		e := e // capture
		var hooks *host.ProxyHooks
		if mode == "per-identity" {
			st := e.state
			svcName := e.name
			hooks = &host.ProxyHooks{
				OnConnect: func(zitiIdentity string) error {
					username := ca.DeriveUsername(zitiIdentity)
					if username == "" {
						return fmt.Errorf("derived empty username from identity %q", zitiIdentity)
					}
					perms := st.get().Resolve(zitiIdentity, globalGroups, globalSudoersRule)
					slog.Info("per-identity connect",
						"service", svcName,
						"identity", zitiIdentity,
						"username", username,
						"groups", perms.Groups,
						"has_sudoers", perms.SudoersRule != "")
					return mgr.EnsureUser(username, perms)
				},
				OnDisconnect: func(zitiIdentity string) {
					username := ca.DeriveUsername(zitiIdentity)
					if username == "" {
						slog.Error("derived empty username on disconnect", "identity", zitiIdentity)
						return
					}
					slog.Info("per-identity disconnect",
						"service", svcName,
						"identity", zitiIdentity,
						"username", username)
					if err := mgr.ReleaseUser(username); err != nil {
						slog.Error("ReleaseUser failed", "username", username, "err", err)
					}
				},
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			host.Proxy(e.listener, defaultSSHTarget, hooks, &connWg)
		}()
	}

	// Install signal handler. On SIGTERM or SIGINT, close all listeners so
	// that host.Proxy goroutines return. In-flight connections are tracked via
	// a per-connection WaitGroup and drained before we exit.
	const drainTimeout = 30 * time.Second
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, stopping proxy listeners", "signal", sig)
		if _, err := daemon.SdNotify(false, "STOPPING=1"); err != nil {
			slog.Debug("sd_notify STOPPING failed", "err", err)
		}
		for _, e := range entries {
			if err := e.listener.Close(); err != nil {
				slog.Debug("listener close on signal", "service", e.name, "err", err)
			}
		}
	}()

	// Wait for all Proxy goroutines to return (i.e. all listeners closed).
	wg.Wait()
	signal.Stop(sigCh)
	slog.Info("proxy listeners closed, draining in-flight connections")

	done := make(chan struct{})
	go func() {
		connWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("all connections drained, exiting cleanly")
	case <-time.After(drainTimeout):
		slog.Warn("drain timeout exceeded; some connections may have been dropped", "timeout", drainTimeout)
	}

	return nil
}

// runInspect authenticates using the given identity, fetches the
// ziti-ssh-host.v1 config for each requested service, and prints a formatted
// permissions table. Exits without opening any listeners.
func runInspect(identityFile string, serviceNames []string, zitiTimeout time.Duration) error {
	zitiCtx, err := newZitiContextWithConfigTypes(identityFile, zitiSSHHostConfigType)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	globalSudoersRule := os.Getenv("ZITI_SUDOERS_RULE")
	globalGroups := parseGlobalGroups()

	for _, svcName := range serviceNames {
		_, ok := zitiCtx.GetService(svcName)
		if !ok {
			fmt.Printf("Service: %s\n  [NOT VISIBLE — check bind policy]\n\n", svcName)
			continue
		}

		pc, err := loadPermissionsConfig(zitiCtx, svcName)
		if err != nil {
			fmt.Printf("Service: %s\n  error reading config: %v\n\n", svcName, err)
			continue
		}

		fmt.Printf("Service: %s\n", svcName)
		if pc == nil {
			fmt.Printf("  Config type %s: not attached\n\n", zitiSSHHostConfigType)
		} else {
			fmt.Printf("  Config type %s: present\n\n", zitiSSHHostConfigType)
			printPermissionsTable(pc)
		}
		printGlobalFallbacks(globalGroups, globalSudoersRule)
		fmt.Println()
	}

	return nil
}

// printPermissionsTable prints a formatted table of identity → permissions
// rows for the given PermissionsConfig.
func printPermissionsTable(pc *host.PermissionsConfig) {
	if len(pc.Permissions) == 0 {
		fmt.Println("  (no identity entries in config)")
		return
	}

	const (
		colIdentity  = 21
		colUsername  = 17
		colGroups    = 17
		colSudoers   = 0 // no fixed width — last column
	)

	hdr := fmt.Sprintf("  %-*s  %-*s  %-*s  %s",
		colIdentity, "Identity",
		colUsername, "Linux username",
		colGroups, "Groups",
		"Sudoers rule")
	sep := fmt.Sprintf("  %-*s  %-*s  %-*s  %s",
		colIdentity, strings.Repeat("-", colIdentity),
		colUsername, strings.Repeat("-", colUsername),
		colGroups, strings.Repeat("-", colGroups),
		strings.Repeat("-", 40))

	fmt.Println(hdr)
	fmt.Println(sep)

	// Sort identities for deterministic output.
	identities := make([]string, 0, len(pc.Permissions))
	for id := range pc.Permissions {
		identities = append(identities, id)
	}
	sortStrings(identities)

	for _, id := range identities {
		perms := pc.Permissions[id]
		username := ca.DeriveUsername(id)

		groupsStr := "(none)"
		if len(perms.Groups) > 0 {
			groupsStr = strings.Join(perms.Groups, ", ")
		}
		sudoersStr := "(none)"
		if perms.SudoersRule != "" {
			sudoersStr = perms.SudoersRule
		}

		fmt.Printf("  %-*s  %-*s  %-*s  %s\n",
			colIdentity, id,
			colUsername, username,
			colGroups, groupsStr,
			sudoersStr)
	}
	fmt.Println()
}

// printGlobalFallbacks prints the global fallback group and sudoers values.
func printGlobalFallbacks(globalGroups []string, globalSudoersRule string) {
	groupsStr := "(not set)"
	if len(globalGroups) > 0 {
		groupsStr = strings.Join(globalGroups, ", ")
	}
	sudoersStr := "(not set)"
	if globalSudoersRule != "" {
		sudoersStr = globalSudoersRule
	}
	fmt.Printf("  Global fallback groups:  %s\n", groupsStr)
	fmt.Printf("  Global fallback sudoers: %s\n", sudoersStr)
}

// sortStrings sorts ss in-place (avoids importing sort at the package level
// since we only need it here).
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}

// Compile-time assertion: zitiEdge.Conn must implement the dialerNamer
// interface that host.proxyConn uses to extract the caller's Ziti identity
// name. This keeps the zitiEdge import live and verifies SDK compatibility.
var _ interface{ GetDialerIdentityName() string } = (zitiEdge.Conn)(nil)
