// Command ziti-ssh-host manages an SSH host's integration with an OpenZiti network.
//
// Subcommands:
//
//	enroll --jwt <path>   Enroll this host as a Ziti identity, configure sshd to
//	                      trust the CA, and reload sshd.
//
//	run                   Listen on the Ziti ssh service and proxy connections to
//	                      the local sshd on 127.0.0.1:22.
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
	defaultIdentityFile   = "/etc/ziti-ssh-host/identity.json"
	defaultCaService      = "ssh-ca"
	defaultSSHService     = "ssh"
	defaultSSHTarget      = "127.0.0.1:22"
	sshdConfFile          = "/etc/ssh/sshd_config.d/ziti-ssh.conf"
	sshdCAPubKeyFile      = "/etc/ssh/ziti_ca.pub"
	userManagerStateFile  = "/var/lib/ziti-ssh-host/managed-users"
)

func main() {
	var (
		identityFlag   string
		caServiceFlag  string
		sshServiceFlag string
	)

	root := &cobra.Command{
		Use:   "ziti-ssh-host",
		Short: "SSH host daemon for OpenZiti networks",
	}

	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Path to Ziti identity file (or ZITI_IDENTITY, default: "+defaultIdentityFile+")")
	root.PersistentFlags().StringVar(&caServiceFlag, "ca-service", "", "Ziti service name for the SSH CA (or ZITI_CA_SERVICE, default: "+defaultCaService+")")
	root.PersistentFlags().StringVar(&sshServiceFlag, "ssh-service", "", "Ziti service name for SSH (or ZITI_SSH_SERVICE, default: "+defaultSSHService+")")

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
			sshService := config.EnvOrFlag(sshServiceFlag, "ZITI_SSH_SERVICE", defaultSSHService)
			mode := config.EnvOrFlag(modeFlag, "ZITI_SSH_MODE", "shared")
			if mode != "shared" && mode != "per-identity" {
				return fmt.Errorf("--mode must be \"shared\" or \"per-identity\", got %q", mode)
			}
			return runProxy(identityFile, sshService, mode)
		},
	}
	runCmd.Flags().StringVar(&modeFlag, "mode", "", "Principal mode: \"shared\" (default) or \"per-identity\" (or set ZITI_SSH_MODE)")

	root.AddCommand(enrollCmd, runCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
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

// runProxy initializes a Ziti context, listens on the ssh service using the
// host's identity name as the terminator address, and proxies all connections
// to the local sshd.
//
// In "per-identity" mode a UserManager is created, orphan cleanup is run at
// startup, and ProxyHooks are wired to create/delete Linux users as sessions
// open and close.
func runProxy(identityFile, sshService, mode string) error {
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	if err := zitiCtx.Authenticate(); err != nil {
		return fmt.Errorf("Ziti authenticate: %w", err)
	}

	listenOpts := &ziti.ListenOptions{
		BindUsingEdgeIdentity: true,
	}
	listener, err := zitiCtx.ListenWithOptions(sshService, listenOpts)
	if err != nil {
		return fmt.Errorf("listen on Ziti service %q: %w", sshService, err)
	}
	defer listener.Close()

	slog.Info("proxying", "service", sshService, "target", defaultSSHTarget, "mode", mode)

	// Notify systemd that the service is ready to accept connections.
	// This is a no-op when not running under systemd (NOTIFY_SOCKET is unset).
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		slog.Debug("sd_notify READY failed (not running under systemd?)", "err", err)
	}

	var hooks *host.ProxyHooks

	if mode == "per-identity" {
		sudoersRule := os.Getenv("ZITI_SUDOERS_RULE")
		cleanupOnDisconnect := os.Getenv("ZITI_USER_CLEANUP") != "false"
		mgr := host.NewUserManager(userManagerStateFile, sudoersRule, cleanupOnDisconnect)

		slog.Info("running orphan user cleanup")
		if err := mgr.CleanupOrphans(); err != nil {
			// Log but do not abort — a cleanup failure is not fatal to startup.
			slog.Error("orphan cleanup failed", "err", err)
		}

		hooks = &host.ProxyHooks{
			OnConnect: func(connIdentity string) error {
				username := ca.DeriveUsername(connIdentity)
				if username == "" {
					return fmt.Errorf("derived empty username from identity %q", connIdentity)
				}
				slog.Info("per-identity connect", "identity", connIdentity, "username", username)
				return mgr.EnsureUser(username)
			},
			OnDisconnect: func(connIdentity string) {
				username := ca.DeriveUsername(connIdentity)
				if username == "" {
					slog.Error("derived empty username on disconnect", "identity", connIdentity)
					return
				}
				slog.Info("per-identity disconnect", "identity", connIdentity, "username", username)
				if err := mgr.ReleaseUser(username); err != nil {
					slog.Error("ReleaseUser failed", "username", username, "err", err)
				}
			},
		}
	}

	// Install signal handler. On SIGTERM or SIGINT, close the listener so
	// that host.Proxy returns. In-flight connections are tracked via wg and
	// drained for up to drainTimeout before we exit.
	const drainTimeout = 30 * time.Second
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup

	go func() {
		sig := <-sigCh
		slog.Info("received signal, stopping proxy listener", "signal", sig)
		// Notify systemd that the service is beginning to shut down.
		if _, err := daemon.SdNotify(false, "STOPPING=1"); err != nil {
			slog.Debug("sd_notify STOPPING failed", "err", err)
		}
		if err := listener.Close(); err != nil {
			slog.Debug("listener close on signal", "err", err)
		}
	}()

	// host.Proxy blocks until the listener is closed.
	host.Proxy(listener, defaultSSHTarget, hooks, &wg)

	signal.Stop(sigCh)
	slog.Info("proxy listener closed, draining in-flight connections")

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

	return nil
}

// Compile-time assertion: zitiEdge.Conn must implement the dialerNamer
// interface that host.proxyConn uses to extract the caller's Ziti identity
// name. This keeps the zitiEdge import live and verifies SDK compatibility.
var _ interface{ GetDialerIdentityName() string } = (zitiEdge.Conn)(nil)
