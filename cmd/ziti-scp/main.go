// Command ziti-scp copies files to and from remote hosts over an OpenZiti
// network using the SFTP subsystem. It mirrors the behaviour of scp(1) but
// operates exclusively through the Ziti overlay — port 22 is never exposed
// externally.
//
// Usage:
//
//	ziti-scp [flags] <src>... <dst>
//
// Where <src> and <dst> are either a local path or a remote specification of
// the form [user@]host:path. At least one side must be remote.
//
// Examples:
//
//	ziti-scp /local/file alice@web-server:/remote/dir/
//	ziti-scp alice@web-server:/remote/file /local/dir/
//	ziti-scp -r /local/dir alice@web-server:/remote/dir/
//	ziti-scp file1 file2 alice@web-server:/remote/dir/
//
// Config file: ~/.config/ziti-ssh/config.yaml (respects XDG_CONFIG_HOME).
// Precedence: CLI flag > config file > built-in default.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	ziti "github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/edwardm/ziti-ssh/client"
	"github.com/edwardm/ziti-ssh/config"
)

// ---------------------------------------------------------------------------
// Config file types (mirrors cmd/ziti-ssh)
// ---------------------------------------------------------------------------

// Config is the structure of ~/.config/ziti-ssh/config.yaml.
type Config struct {
	Identity   string     `yaml:"identity"`
	CAService  string     `yaml:"ca_service"`
	SSHService string     `yaml:"ssh_service"`
	SSHKeyPath string     `yaml:"ssh_key_path"`
	Mode       string     `yaml:"mode"`
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
// Argument parsing
// ---------------------------------------------------------------------------

// remoteSpec represents a parsed [user@]host:path remote specification.
type remoteSpec struct {
	user string
	host string
	path string
}

// parseArg parses a single scp-style argument. It returns (isRemote, remoteSpec, localPath).
// A remote specification is any argument containing ":" that is not an absolute or
// relative path (i.e. does not start with "/" or ".").
func parseArg(arg string) (isRemote bool, remote remoteSpec, localPath string) {
	// Detect "host:path" — the colon must appear before any "/" to avoid
	// treating absolute paths like "/foo/bar" as remote specs.
	colonIdx := strings.Index(arg, ":")
	if colonIdx > 0 {
		hostPart := arg[:colonIdx]
		// Make sure the host part does not look like a Windows absolute path
		// (e.g. "C:") — a single letter followed by ":" is a drive letter.
		if len(hostPart) > 1 || (len(hostPart) == 1 && (hostPart[0] < 'A' || hostPart[0] > 'Z') && (hostPart[0] < 'a' || hostPart[0] > 'z')) {
			pathPart := arg[colonIdx+1:]
			u, h := splitUserHost(hostPart)
			return true, remoteSpec{user: u, host: h, path: pathPart}, ""
		}
	}
	return false, remoteSpec{}, arg
}

// splitUserHost splits "user@host" into (user, host). If no "@" is present the
// current OS username is used.
func splitUserHost(hostPart string) (u, h string) {
	if idx := strings.IndexByte(hostPart, '@'); idx >= 0 {
		return hostPart[:idx], hostPart[idx+1:]
	}
	cur, err := user.Current()
	if err == nil {
		return cur.Username, hostPart
	}
	return "", hostPart
}

// ---------------------------------------------------------------------------
// SSH key helpers (mirrors cmd/ziti-ssh)
// ---------------------------------------------------------------------------

var candidateKeys = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

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
		p := filepath.Join(sshDir, name)
		if _, err := os.Stat(p); err == nil {
			slog.Info("auto-detected SSH key", "path", p)
			return p, nil
		}
	}
	return "", fmt.Errorf("no SSH key found; provide one with --key or run: ssh-keygen -t ed25519")
}

func deriveCertPath(privKeyPath string) string {
	return strings.TrimSuffix(privKeyPath, ".pub") + "-cert.pub"
}

// ---------------------------------------------------------------------------
// Sign helpers (mirrors runSign in cmd/ziti-ssh)
// ---------------------------------------------------------------------------

type signParams struct {
	identityFile string
	caService    string
	keyFile      string
	oidcIssuer   string
}

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

	slog.Info("using SSH key", "private", privKeyPath, "public", pubKeyPath)

	zitiCtx, err := ziti.NewContextFromFile(p.identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", p.identityFile, err)
	}
	defer zitiCtx.Close()

	if err := zitiCtx.Authenticate(); err != nil {
		return fmt.Errorf("Ziti authenticate: %w", err)
	}

	slog.Info("dialing CA service", "service", p.caService)
	conn, err := zitiCtx.Dial(p.caService)
	if err != nil {
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

	fmt.Printf("Certificate written to %s\n", certPath)
	return nil
}

// ---------------------------------------------------------------------------
// Enroll subcommand logic (mirrors cmd/ziti-ssh)
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
// SCP copy logic
// ---------------------------------------------------------------------------

// scpParams holds all resolved settings for the copy operation.
type scpParams struct {
	identityFile string
	caService    string
	sshService   string
	keyFile      string
	recursive    bool
	preserve     bool
	quiet        bool
	// srcs and dst are the raw argument strings as provided by the user.
	srcs []string
	dst  string
}

func runSCP(p scpParams) error {
	// Parse all source arguments and the destination.
	type srcEntry struct {
		isRemote bool
		remote   remoteSpec
		local    string
	}

	var entries []srcEntry
	for _, src := range p.srcs {
		isRemote, remote, local := parseArg(src)
		entries = append(entries, srcEntry{isRemote: isRemote, remote: remote, local: local})
	}

	isDstRemote, dstRemote, dstLocal := parseArg(p.dst)

	// Validate: exactly one side (source or destination) may be remote.
	srcRemoteCount := 0
	for _, e := range entries {
		if e.isRemote {
			srcRemoteCount++
		}
	}

	switch {
	case srcRemoteCount > 0 && isDstRemote:
		return fmt.Errorf("cannot copy between two remote hosts")
	case srcRemoteCount == 0 && !isDstRemote:
		return fmt.Errorf("at least one argument must be a remote specification ([user@]host:path)")
	case srcRemoteCount > 0 && srcRemoteCount != len(entries):
		return fmt.Errorf("all sources must be either all local or all remote")
	}

	// Ensure all remote sources share the same host (for a single Ziti dial).
	var remoteHost, remoteUser string
	if isDstRemote {
		remoteHost = dstRemote.host
		remoteUser = dstRemote.user
	} else {
		remoteHost = entries[0].remote.host
		remoteUser = entries[0].remote.user
		for _, e := range entries[1:] {
			if e.remote.host != remoteHost {
				return fmt.Errorf("all remote sources must refer to the same host")
			}
		}
	}

	// Resolve the SSH key and check if the cert needs refresh.
	privKeyPath, err := resolveKey(p.keyFile)
	if err != nil {
		return err
	}
	certPath := deriveCertPath(privKeyPath)

	if client.CertNeedsRefresh(certPath) {
		slog.Info("certificate missing or expiring soon — obtaining fresh certificate")
		if err := runSign(signParams{
			identityFile: p.identityFile,
			caService:    p.caService,
			keyFile:      privKeyPath,
		}); err != nil {
			return fmt.Errorf("auto-sign: %w", err)
		}
	}

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

	if err := zitiCtx.Authenticate(); err != nil {
		return fmt.Errorf("Ziti authenticate: %w", err)
	}

	// Resolve the Ziti service and optional terminator address.
	dialService := p.sshService
	terminatorAddr := remoteHost

	if _, ok := zitiCtx.GetService(remoteHost); ok {
		dialService = remoteHost
		terminatorAddr = ""
	}

	var netConn net.Conn
	if terminatorAddr != "" {
		slog.Info("dialing SSH service", "service", dialService, "terminator", terminatorAddr)
		dialOpts := &ziti.DialOptions{
			Identity: terminatorAddr,
		}
		netConn, err = zitiCtx.DialWithOptions(dialService, dialOpts)
	} else {
		slog.Info("dialing SSH service", "service", dialService)
		netConn, err = zitiCtx.Dial(dialService)
	}
	if err != nil {
		return fmt.Errorf("dial Ziti service %q: %w", dialService, err)
	}

	// Build the local/remote path lists for RunSFTP.
	if isDstRemote {
		// Upload: srcs are local, dst is remote.
		var localPaths []string
		for _, e := range entries {
			localPaths = append(localPaths, e.local)
		}
		slog.Info("uploading", "user", remoteUser, "host", remoteHost, "remote_path", dstRemote.path, "local_paths", localPaths)
		return client.RunSFTP(netConn, remoteUser, remoteHost, signer,
			true, localPaths, dstRemote.path,
			p.recursive, p.preserve, p.quiet)
	}

	// Download: srcs are remote, dst is local.
	var remotePaths []string
	for _, e := range entries {
		remotePaths = append(remotePaths, e.remote.path)
	}
	slog.Info("downloading", "user", remoteUser, "host", remoteHost, "remote_paths", remotePaths, "local_dst", dstLocal)
	return client.RunSFTP(netConn, remoteUser, remoteHost, signer,
		false, remotePaths, dstLocal,
		p.recursive, p.preserve, p.quiet)
}

// version is set at build time via -ldflags "-X main.version=<ver>".
var version = "dev"

// ---------------------------------------------------------------------------
// main — cobra command tree
// ---------------------------------------------------------------------------

func main() {
	var (
		identityFlag string
		configFlag   string
		versionFlag  bool

		cfg *Config
	)

	root := &cobra.Command{
		Use:   "ziti-scp [flags] <src>... <dst>",
		Short: "Copy files over OpenZiti using SFTP",
		Long: `ziti-scp copies files to and from remote hosts over an OpenZiti network using
the SFTP subsystem. It mirrors scp(1) but all traffic flows through the Ziti
overlay — port 22 is never exposed externally.

At least one of <src> or <dst> must be a remote specification of the form:
  [user@]host:path

If the remote hostname matches a Ziti service name it is dialled directly.
Otherwise it is used as a terminator address on --ssh-service (default: "ssh").

Examples:

  # Upload a file
  ziti-scp /local/file alice@web-server:/remote/dir/

  # Download a file
  ziti-scp alice@web-server:/remote/file /local/dir/

  # Recursive directory copy
  ziti-scp -r /local/dir alice@web-server:/remote/dir/

  # Multiple sources
  ziti-scp file1 file2 alice@web-server:/remote/dir/

Certificates are obtained from the ziti-ssh-ca service and cached in
~/.ssh/<key>-cert.pub, refreshed automatically when fewer than 30 minutes
of validity remain.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if versionFlag {
				return nil
			}
			return cobra.MinimumNArgs(2)(cmd, args)
		},
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if versionFlag {
				fmt.Printf("ziti-scp version %s\n", version)
				os.Exit(0)
			}
			cfgPath := configFlag
			if cfgPath == "" {
				cfgPath = defaultConfigPath()
			}
			var err error
			cfg, err = loadConfig(cfgPath)
			return err
		},
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

			// args[0..len-2] are sources; args[len-1] is destination.
			srcs := args[:len(args)-1]
			dst := args[len(args)-1]

			return runSCP(scpParams{
				identityFile: identityFile,
				caService:    caService,
				sshService:   sshService,
				keyFile:      resolvedKey,
				recursive:    recursiveFlag,
				preserve:     preserveFlag,
				quiet:        quietFlag,
				srcs:         srcs,
				dst:          dst,
			})
		},
	}

	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Ziti identity file path (or ZITI_IDENTITY)")
	root.PersistentFlags().StringVar(&configFlag, "config", "", "Config file path (default: ~/.config/ziti-ssh/config.yaml)")
	root.PersistentFlags().BoolVarP(&versionFlag, "version", "V", false, "Print version and exit")

	root.Flags().StringVar(&caServiceFlag, "ca-service", "", "CA service name (or ZITI_CA_SERVICE, default: ssh-ca)")
	root.Flags().StringVar(&sshServiceFlag, "ssh-service", "", "SSH service name (or ZITI_SSH_SERVICE, default: ssh)")
	root.Flags().StringVar(&keyFlag, "key", "", "SSH private key path (default: auto-detect from ~/.ssh/)")
	root.Flags().BoolVarP(&recursiveFlag, "recursive", "r", false, "Recursively copy entire directories")
	root.Flags().BoolVarP(&preserveFlag, "preserve", "p", false, "Preserve file timestamps and permissions")
	root.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress progress output")

	// --------------------------------------------------------------- version
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ziti-scp version %s\n", version)
		},
	}
	root.AddCommand(versionCmd)

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
  ziti-scp enroll --jwt alice.jwt
  ziti-scp enroll --jwt alice.jwt --out ~/.config/ziti-ssh/alice.json`,
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

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// Package-level flag variables referenced inside root.RunE closure.
var (
	caServiceFlag  string
	sshServiceFlag string
	keyFlag        string
	recursiveFlag  bool
	preserveFlag   bool
	quietFlag      bool
)
