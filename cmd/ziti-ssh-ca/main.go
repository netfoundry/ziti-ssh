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
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/edwardm/ziti-ssh/ca"
	"github.com/edwardm/ziti-ssh/config"

	zitiEdge "github.com/openziti/sdk-golang/ziti/edge"

	ziti "github.com/openziti/sdk-golang/ziti"
)

func main() {
	var (
		identityFlag string
		caKeyFlag    string
		serviceFlag  string
		principalFlag string
		modeFlag     string
		certTTLFlag  string
	)

	root := &cobra.Command{
		Use:   "ziti-ssh-ca",
		Short: "SSH Certificate Authority service over OpenZiti",
		RunE: func(cmd *cobra.Command, args []string) error {
			identityFile := config.EnvOrFlag(identityFlag, "ZITI_IDENTITY", "")
			caKeyFile := config.EnvOrFlag(caKeyFlag, "ZITI_CA_KEY", "")
			serviceName := config.EnvOrFlag(serviceFlag, "ZITI_CA_SERVICE", "ssh-ca")
			principal := config.EnvOrFlag(principalFlag, "ZITI_SSH_PRINCIPAL", "ziggy")
			mode := config.EnvOrFlag(modeFlag, "ZITI_SSH_MODE", "shared")
			certTTLStr := config.EnvOrFlag(certTTLFlag, "ZITI_CERT_TTL", "8h")

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

			return run(identityFile, caKeyFile, serviceName, principal, mode, certTTL)
		},
	}

	root.Flags().StringVar(&identityFlag, "identity", "", "Path to Ziti identity file (or set ZITI_IDENTITY)")
	root.Flags().StringVar(&caKeyFlag, "ca-key", "", "Path to CA private key (Ed25519) (or set ZITI_CA_KEY)")
	root.Flags().StringVar(&serviceFlag, "service", "", "Ziti service name to bind (or set ZITI_CA_SERVICE, default: ssh-ca)")
	root.Flags().StringVar(&principalFlag, "principal", "", "SSH certificate principal in shared mode (or set ZITI_SSH_PRINCIPAL, default: ziggy)")
	root.Flags().StringVar(&modeFlag, "mode", "", "Principal mode: \"shared\" (default) or \"per-identity\" (or set ZITI_SSH_MODE)")
	root.Flags().StringVar(&certTTLFlag, "cert-ttl", "", "Certificate validity duration (or set ZITI_CERT_TTL, default: 8h)")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(identityFile, caKeyFile, serviceName, principal, mode string, certTTL time.Duration) error {
	// Load CA key.
	signer, caPub, err := ca.LoadKey(caKeyFile)
	if err != nil {
		return fmt.Errorf("load CA key: %w", err)
	}
	slog.Info("CA key loaded", "service", serviceName, "mode", mode, "principal", principal)

	caPubBytes := ca.PublicKeyBytes(caPub)

	// Initialize Ziti context.
	zitiCtx, err := ziti.NewContextFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	if err := zitiCtx.Authenticate(); err != nil {
		return fmt.Errorf("Ziti authenticate: %w", err)
	}

	// Bind the service.
	listener, err := zitiCtx.Listen(serviceName)
	if err != nil {
		return fmt.Errorf("listen on Ziti service %q: %w", serviceName, err)
	}
	defer listener.Close()

	slog.Info("listening", "service", serviceName)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("accept failed", "err", err)
			return fmt.Errorf("accept: %w", err)
		}
		go handleConn(conn, signer, caPubBytes, principal, mode, certTTL)
	}
}

// handleConn serves a single incoming Ziti connection.
// It reads one line from the client:
//   - empty line  → send CA public key
//   - public key  → sign and return certificate
//
// In "shared" mode the principal comes from the operator-configured flag.
// In "per-identity" mode the principal is derived from the caller's Ziti identity
// name via ca.DeriveUsername.
func handleConn(conn net.Conn, signer ssh.Signer, caPubBytes []byte, principal, mode string, certTTL time.Duration) {
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

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Error("read request", "err", err)
		return
	}
	line = strings.TrimSpace(line)

	if line == "" {
		// Client requested the CA public key.
		if _, err := conn.Write(caPubBytes); err != nil {
			log.Error("write CA public key", "err", err)
		} else {
			log.Info("served CA public key")
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

// callerIdentity extracts the Ziti identity name from a net.Conn. The Ziti
// SDK's edge.Listener.Accept() returns connections that implement edge.Conn,
// which exposes GetDialerIdentityName(). If the type assertion fails (e.g.
// in tests with plain net.Conn), an empty string is returned.
func callerIdentity(conn net.Conn) string {
	if ec, ok := conn.(zitiEdge.Conn); ok {
		return ec.GetDialerIdentityName()
	}
	// Fallback: try ServiceConn (the narrower interface).
	type dialerNamer interface {
		GetDialerIdentityName() string
	}
	if dn, ok := conn.(dialerNamer); ok {
		return dn.GetDialerIdentityName()
	}
	return ""
}
