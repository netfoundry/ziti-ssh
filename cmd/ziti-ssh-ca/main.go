// Command ziti-ssh-ca is an SSH Certificate Authority service that runs over an
// OpenZiti network. It signs short-lived SSH user certificates for callers
// whose Ziti identity is authorized to dial the configured service. The Ziti
// identity name is embedded in the certificate Key ID for audit purposes.
//
// Wire protocol (over the raw Ziti connection):
//   - Send an empty line ("\n")   → receive the CA public key in authorized_keys format
//   - Send an SSH public key line → receive a signed SSH certificate in authorized_keys format
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/edwardm/ziti-ssh/ca"
	"github.com/edwardm/ziti-ssh/config"
	"github.com/edwardm/ziti-ssh/internal/ratelimit"

	ziti "github.com/openziti/sdk-golang/ziti"
	zitiEnroll "github.com/openziti/sdk-golang/ziti/enroll"
	zitiEdge "github.com/openziti/sdk-golang/ziti/edge"
)

// version is set at build time via -ldflags "-X main.version=<ver>".
var version = "dev"

func main() {
	var (
		identityFlag    string
		caKeyFlag       string
		serviceFlag     string
		principalFlag   string
		modeFlag        string
		certTTLFlag     string
		rateLimitFlag   string
		rateBurstFlag   string
		zitiTimeoutFlag string
		versionFlag     bool
	)

	root := &cobra.Command{
		Use:   "ziti-ssh-ca",
		Short: "SSH Certificate Authority service over OpenZiti",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if versionFlag {
				fmt.Printf("ziti-ssh-ca version %s\n", version)
				os.Exit(0)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", "")
			caKeyFile := config.EnvOrFlag(caKeyFlag, "ZITI_CA_KEY", "")
			serviceName := config.EnvOrFlag(serviceFlag, "ZITI_CA_SERVICE", "ssh-ca")
			principal := config.EnvOrFlag(principalFlag, "ZITI_SSH_PRINCIPAL", "ziggy")
			mode := config.EnvOrFlag(modeFlag, "ZITI_SSH_MODE", "shared")
			certTTLStr := config.EnvOrFlag(certTTLFlag, "ZITI_CERT_TTL", "8h")
			rateLimitStr := config.EnvOrFlag(rateLimitFlag, "ZITI_RATE_LIMIT", "5")
			rateBurstStr := config.EnvOrFlag(rateBurstFlag, "ZITI_RATE_BURST", "3")
			zitiTimeoutStr := config.EnvOrFlag(zitiTimeoutFlag, "ZITI_TIMEOUT", "30s")

			if identityFile == "" {
				return fmt.Errorf("--identity (or ZITI_IDENTITY) is required")
			}
			if caKeyFile == "" {
				return fmt.Errorf("--ca-key (or ZITI_CA_KEY) is required")
			}
			if mode != "shared" && mode != "per-identity" {
				return fmt.Errorf("--mode must be \"shared\" or \"per-identity\", got %q", mode)
			}

			certTTL, err := time.ParseDuration(certTTLStr)
			if err != nil {
				return fmt.Errorf("--cert-ttl (or ZITI_CERT_TTL): invalid duration %q: %w", certTTLStr, err)
			}
			if certTTL <= 0 {
				return fmt.Errorf("--cert-ttl (or ZITI_CERT_TTL) must be greater than zero, got %q", certTTLStr)
			}

			zitiTimeout, err := time.ParseDuration(zitiTimeoutStr)
			if err != nil {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT): invalid duration %q: %w", zitiTimeoutStr, err)
			}
			if zitiTimeout <= 0 {
				return fmt.Errorf("--ziti-timeout (or ZITI_TIMEOUT) must be greater than zero, got %q", zitiTimeoutStr)
			}

			rateLimit, err := strconv.ParseFloat(rateLimitStr, 64)
			if err != nil || rateLimit <= 0 {
				return fmt.Errorf("--rate-limit (or ZITI_RATE_LIMIT): must be a positive number, got %q", rateLimitStr)
			}

			rateBurst, err := strconv.Atoi(rateBurstStr)
			if err != nil || rateBurst < 1 {
				return fmt.Errorf("--rate-burst (or ZITI_RATE_BURST): must be a positive integer, got %q", rateBurstStr)
			}

			return run(identityFile, caKeyFile, serviceName, principal, mode, certTTL, rateLimit, rateBurst, zitiTimeout)
		},
	}

	root.Flags().StringVar(&identityFlag, "identity", "", "Path to Ziti identity file (or set ZITI_IDENTITY)")
	root.Flags().StringVar(&caKeyFlag, "ca-key", "", "Path to CA private key (Ed25519) (or set ZITI_CA_KEY)")
	root.Flags().StringVar(&serviceFlag, "service", "", "Ziti service name to bind (or set ZITI_CA_SERVICE, default: ssh-ca)")
	root.Flags().StringVar(&principalFlag, "principal", "", "SSH certificate principal in shared mode (or set ZITI_SSH_PRINCIPAL, default: ziggy)")
	root.Flags().StringVar(&modeFlag, "mode", "", "Principal mode: \"shared\" (default) or \"per-identity\" (or set ZITI_SSH_MODE)")
	root.Flags().StringVar(&certTTLFlag, "cert-ttl", "", "Certificate validity duration (or set ZITI_CERT_TTL, default: 8h)")
	root.Flags().StringVar(&rateLimitFlag, "rate-limit", "", "Max cert signing requests per minute per identity (or set ZITI_RATE_LIMIT, default: 5)")
	root.Flags().StringVar(&rateBurstFlag, "rate-burst", "", "Burst allowance for per-identity rate limiter (or set ZITI_RATE_BURST, default: 3)")
	root.PersistentFlags().StringVar(&zitiTimeoutFlag, "ziti-timeout", "", "Timeout for Ziti network operations (or set ZITI_TIMEOUT, default: 30s)")
	root.PersistentFlags().BoolVarP(&versionFlag, "version", "V", false, "Print version and exit")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ziti-ssh-ca version %s\n", version)
		},
	}
	// ------------------------------------------------------------------ enroll
	var (
		enrollJWTFlag string
		enrollOutFlag string
	)
	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a Ziti identity from a JWT file",
		Long: `enroll reads the one-time enrollment JWT produced by "ziti edge create identity"
and produces an enrolled identity JSON file that can be used with --identity.

The output path defaults to /etc/ziti-ssh-ca/identity.json.

Example:
  ziti-ssh-ca enroll --jwt /tmp/ssh-ca-server.jwt
  ziti-ssh-ca enroll --jwt /tmp/ssh-ca-server.jwt --out /etc/ziti-ssh-ca/identity.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outPath := enrollOutFlag
			if outPath == "" {
				outPath = "/etc/ziti-ssh-ca/identity.json"
			}
			return runEnroll(enrollJWTFlag, outPath)
		},
	}
	enrollCmd.Flags().StringVar(&enrollJWTFlag, "jwt", "", "Path to enrollment JWT file (required)")
	enrollCmd.Flags().StringVar(&enrollOutFlag, "out", "", "Output path for identity JSON (default: /etc/ziti-ssh-ca/identity.json)")
	_ = enrollCmd.MarkFlagRequired("jwt")

	root.AddCommand(versionCmd)
	root.AddCommand(enrollCmd)
	root.AddCommand(configCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// runEnroll enrolls a Ziti identity from a one-time JWT file and writes the
// resulting identity JSON to outPath (mode 0600).
func runEnroll(jwtPath, outPath string) error {
	jwtBytes, err := os.ReadFile(jwtPath)
	if err != nil {
		return fmt.Errorf("read JWT from %q: %w", jwtPath, err)
	}
	jwtString := strings.TrimSpace(string(jwtBytes))

	token, jwtToken, err := zitiEnroll.ParseToken(jwtString)
	if err != nil {
		return fmt.Errorf("parse enrollment JWT: %w", err)
	}

	keyAlg := ziti.KeyAlgVar("EC")
	enrollFlags := zitiEnroll.EnrollmentFlags{
		Token:     token,
		JwtToken:  jwtToken,
		JwtString: jwtString,
		KeyAlg:    keyAlg,
	}

	slog.Info("enrolling Ziti identity", "jwt", jwtPath, "out", outPath)
	cfg, err := zitiEnroll.Enroll(enrollFlags)
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
	if err := config.AtomicWriteFile(outPath, cfgJSON, 0600); err != nil {
		return fmt.Errorf("write identity file %q: %w", outPath, err)
	}

	slog.Info("identity enrolled", "path", outPath)
	fmt.Printf("Identity enrolled and written to %s\n", outPath)
	return nil
}

const drainTimeout = 30 * time.Second

// idleLimiterTTL is how long a per-identity limiter entry may go unused before
// it is evicted from the map. Set to 10 minutes — well above any reasonable
// burst window.
const idleLimiterTTL = 10 * time.Minute

func run(identityFile, caKeyFile, serviceName, principal, mode string, certTTL time.Duration, ratePerMinute float64, rateBurst int, zitiTimeout time.Duration) error {
	// Load CA key.
	signer, caPub, err := ca.LoadKey(caKeyFile)
	if err != nil {
		return fmt.Errorf("load CA key: %w", err)
	}
	slog.Info("CA key loaded", "service", serviceName, "mode", mode, "principal", principal,
		"rate_limit_per_min", ratePerMinute, "rate_burst", rateBurst)

	caPubBytes := ca.PublicKeyBytes(caPub)

	// Initialize Ziti context.
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

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

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	// Bind the service.
	var listener zitiEdge.Listener
	if err := config.RunWithTimeout(zitiTimeout, "listen", func() error {
		var listenErr error
		listener, listenErr = zitiCtx.Listen(serviceName)
		if listenErr != nil {
			return fmt.Errorf("listen on Ziti service %q: %w", serviceName, listenErr)
		}
		return nil
	}); err != nil {
		return err
	}

	slog.Info("listening", "service", serviceName)

	// Notify systemd that the service is ready to accept connections.
	// This is a no-op when not running under systemd (NOTIFY_SOCKET is unset).
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		slog.Debug("sd_notify READY failed (not running under systemd?)", "err", err)
	}

	// Build per-identity rate limiter. The eviction goroutine is stopped when
	// the stop channel is closed, which happens after the accept loop exits.
	stopLimiter := make(chan struct{})
	// Convert from requests-per-minute to requests-per-second for rate.Limit.
	rps := ratePerMinute / 60.0
	limiter := ratelimit.New(rps, rateBurst, idleLimiterTTL, stopLimiter)

	// Install signal handler. On SIGTERM or SIGINT, close the listener so
	// that the accept loop exits. In-flight handlers are allowed to finish
	// for up to drainTimeout before we return.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup

	// Signal watcher: close listener on first signal.
	go func() {
		sig := <-sigCh
		slog.Info("received signal, stopping listener", "signal", sig)
		// Notify systemd that the service is beginning to shut down.
		if _, err := daemon.SdNotify(false, "STOPPING=1"); err != nil {
			slog.Debug("sd_notify STOPPING failed", "err", err)
		}
		if err := listener.Close(); err != nil {
			slog.Debug("listener close on signal", "err", err)
		}
	}()

	// Accept loop.
	for {
		conn, err := listener.Accept()
		if err != nil {
			// listener.Close() causes Accept to return an error — this is the
			// normal graceful shutdown path.
			slog.Info("listener closed, draining in-flight connections")
			break
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleConn(c, signer, caPubBytes, principal, mode, certTTL, limiter)
		}(conn)
	}

	// Stop the limiter eviction goroutine now that we're shutting down.
	close(stopLimiter)

	// Wait for in-flight handlers with a drain timeout.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("all connections drained, exiting cleanly")
	case <-time.After(drainTimeout):
		slog.Warn("drain timeout exceeded; some connections may have been dropped", "timeout", drainTimeout)
	}

	signal.Stop(sigCh)
	return nil
}

// handleConn serves a single incoming Ziti connection.
// It reads one line from the client:
//   - empty line  → send CA public key (not rate-limited)
//   - public key  → sign and return certificate (rate-limited per identity)
//
// In "shared" mode the principal comes from the operator-configured flag.
// In "per-identity" mode the principal is derived from the caller's Ziti identity
// name via ca.DeriveUsername.
func handleConn(conn net.Conn, signer ssh.Signer, caPubBytes []byte, principal, mode string, certTTL time.Duration, limiter *ratelimit.Map) {
	defer conn.Close()

	// Extract caller identity. The Ziti listener returns edge.Conn values via
	// AcceptEdge; plain Accept returns a net.Conn wrapper. We type-assert to get
	// the identity name.
	identity := callerIdentity(conn)
	if identity == "" {
		slog.Error("rejected connection: empty Ziti identity")
		return
	}

	log := slog.With("identity", identity)

	// In per-identity mode the principal is derived from the caller's identity.
	effectivePrincipal := principal
	if mode == "per-identity" {
		effectivePrincipal = ca.DeriveUsername(identity)
		if effectivePrincipal == "" {
			log.Error("rejected connection: derived username is empty", "identity", identity)
			return
		}
		log = log.With("derived_principal", effectivePrincipal)
	}

	// Bound the connection lifetime: 30 s is generous for a single-line request.
	// The size cap (4 KiB) is well above any real SSH public key but prevents a
	// slow-sender from holding the connection indefinitely.
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log.Error("set deadline", "err", err)
		return
	}
	const maxRequestBytes = 4096
	reader := bufio.NewReader(io.LimitReader(conn, maxRequestBytes))
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Error("read request", "err", err)
		return
	}
	line = strings.TrimSpace(line)

	if line == "" {
		// Client requested the CA public key — not subject to rate limiting.
		if _, err := conn.Write(caPubBytes); err != nil {
			log.Error("write CA public key", "err", err)
		} else {
			log.Info("served CA public key")
		}
		return
	}

	// Cert signing request — enforce per-identity rate limit.
	if !limiter.Allow(identity) {
		log.Warn("rate limit exceeded, rejecting cert signing request", "identity", identity)
		if _, err := conn.Write([]byte("error: rate limit exceeded\n")); err != nil {
			log.Error("write rate limit error", "err", err)
		}
		return
	}

	// Client sent a public key — parse it and return a signed certificate.
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		log.Error("parse client public key", "err", err)
		return
	}

	certBytes, err := ca.SignCert(signer, pubKey, identity, effectivePrincipal, certTTL)
	if err != nil {
		log.Error("sign certificate", "err", err)
		return
	}

	if _, err := conn.Write(certBytes); err != nil {
		log.Error("write signed cert", "err", err)
		return
	}

	log.Info("issued SSH certificate", "principal", effectivePrincipal, "ttl", certTTL)
}

// callerIdentity extracts the Ziti identity name from a net.Conn.
//
// The SDK sets CallerIdHeader to the dialer's identity name on every dial
// (ziti.go: edgeDialOptions.CallerId = GetCurrentApiSession().GetIdentityName()).
// This is exposed via SourceIdentifier() on edge.Conn.
//
// GetDialerIdentityName() reads a separate header injected by the fabric layer
// that is not always present — SourceIdentifier() is the reliable source.
//
// Returns "" only for plain net.Conn values (e.g. in unit tests).
func callerIdentity(conn net.Conn) string {
	if ec, ok := conn.(zitiEdge.Conn); ok {
		if name := ec.SourceIdentifier(); name != "" {
			return name
		}
		return ec.GetDialerIdentityName()
	}
	// Fallback: structural interface for tests/mocks that don't import edge.
	type sourceIdentifier interface {
		SourceIdentifier() string
	}
	if si, ok := conn.(sourceIdentifier); ok {
		return si.SourceIdentifier()
	}
	return ""
}
