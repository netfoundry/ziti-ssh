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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
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

	"github.com/netfoundry/ziti-ssh/ca"
	"github.com/netfoundry/ziti-ssh/config"
	"github.com/netfoundry/ziti-ssh/host"
)

const (
	defaultIdentityFile  = "/etc/ziti-ssh-host/identity.json"
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
			return runEnroll(jwtPath, identityFile)
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

// runEnroll enrolls this host with the Ziti network, fetches the intermediate
// CA public key from every controller in the cluster, and writes them to the
// sshd TrustedUserCAKeys file. In an HA cluster each controller node has its
// own intermediate CA; all of them must be trusted so that SSH certificates
// issued by any node are accepted.
func runEnroll(jwtPath, identityFile string) error {
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

	// 2. Perform enrollment. The returned *ziti.Config contains the CA chain
	// in cfg.ID.CA (PEM-encoded, "pem:" prefix).
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
	if err := config.AtomicWriteFile(identityFile, cfgJSON, 0600); err != nil {
		return fmt.Errorf("write identity file %q: %w", identityFile, err)
	}
	slog.Info("identity enrolled", "path", identityFile)

	// 4. Build a CA pool from the enrollment response — used to authenticate
	// TLS connections to peer controllers when fetching their CA public keys.
	rootPool, err := buildCAPool(cfg)
	if err != nil {
		return fmt.Errorf("build CA pool from enrollment response: %w", err)
	}

	// 5. Collect the intermediate CA public key from every controller in the
	// cluster. The controller list comes from the "ctrls" JWT claim; falls
	// back to the issuer URL for older controllers that omit the claim.
	ctrlURLs := controllersFromToken(token)
	clusterCAs, err := collectClusterCAs(ctrlURLs, rootPool)
	if err != nil {
		return fmt.Errorf("collect cluster CA public keys: %w", err)
	}
	for _, ca := range clusterCAs {
		slog.Info("trusting controller intermediate CA", "url", ca.ControllerURL)
	}
	caPubBytes := clusterCAsToBytes(clusterCAs)

	// 6. Write sshd configuration.
	if err := host.WriteSSHConfig(caPubBytes, sshdConfFile, sshdCAPubKeyFile); err != nil {
		return fmt.Errorf("write sshd config: %w", err)
	}

	// 7. Reload sshd.
	if err := host.ReloadSSHD(); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}

	slog.Info("enrollment complete",
		"controllers_contacted", len(ctrlURLs),
		"trusted_cas", len(clusterCAs))
	return nil
}

// controllersFromToken returns https:// URL roots for all controllers listed
// in the JWT "ctrls" claim. Falls back to the token issuer for older
// controllers that omit the claim.
func controllersFromToken(token *ziti.EnrollmentClaims) []string {
	if len(token.Controllers) > 0 {
		urls := make([]string, 0, len(token.Controllers))
		for _, ctrl := range token.Controllers {
			urls = append(urls, parseControllerURL(ctrl))
		}
		return urls
	}
	if token.Issuer != "" {
		return []string{token.Issuer}
	}
	return nil
}

// parseControllerURL converts a controller address from the JWT "ctrls" claim
// (e.g. "tls:host:443") to an https:// URL suitable for
// enroll.FetchCertificates. Pass-through for addresses that already carry a
// scheme.
func parseControllerURL(ctrl string) string {
	if strings.HasPrefix(ctrl, "tls:") {
		return "https://" + strings.TrimPrefix(ctrl, "tls:")
	}
	if !strings.Contains(ctrl, "://") {
		return "https://" + ctrl
	}
	return ctrl
}

// buildCAPool constructs an *x509.CertPool from the CA chain embedded in cfg.
// The pool is used to authenticate TLS connections to Ziti controllers when
// fetching their intermediate CA public keys.
func buildCAPool(cfg *ziti.Config) (*x509.CertPool, error) {
	caPEM := strings.TrimPrefix(cfg.ID.CA, "pem:")
	if caPEM == "" {
		return nil, fmt.Errorf("identity config contains no CA chain")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("no valid certificates in CA chain")
	}
	return pool, nil
}

// collectClusterCAPubKeys dials each controller over TLS, reads the
// intermediate CA from the presented certificate chain, and returns all
// unique intermediate CA public keys concatenated in authorized_keys format,
// ready to write to TrustedUserCAKeys.
//
// rootPool is used for TLS validation. Pass nil during enrollment bootstrap,
// before the pool is available (InsecureSkipVerify is used in that case).
// clusterCA pairs a controller URL with the SSH authorized_key line for its
// intermediate CA. Used to track which controller contributed each trusted key
// so that additions and removals can be logged with context.
type clusterCA struct {
	ControllerURL string
	AuthorizedKey []byte // single line in authorized_keys format
}

// collectClusterCAs dials each controller URL over TLS, extracts the
// intermediate CA certificate from the handshake, and returns one clusterCA
// per unique intermediate CA (deduplicated by actual public key bytes, not
// SubjectKeyId which is unreliable across HA nodes).
func collectClusterCAs(urlRoots []string, rootPool *x509.CertPool) ([]clusterCA, error) {
	seen := make(map[string]bool)
	var out []clusterCA

	for _, urlRoot := range urlRoots {
		cert, err := intCAFromController(urlRoot, rootPool)
		if err != nil {
			slog.Warn("could not get intermediate CA from controller", "url", urlRoot, "err", err)
			continue
		}

		// Deduplicate by public key bytes — SubjectKeyId is not reliable
		// (issuers may stamp the same value on distinct certs).
		b, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			slog.Warn("could not marshal CA public key for deduplication",
				"subject", cert.Subject.String(), "err", err)
			continue
		}
		key := fmt.Sprintf("%x", b)
		if seen[key] {
			slog.Debug("controller shares intermediate CA with a peer, skipping duplicate",
				"subject", cert.Subject.String(), "url", urlRoot)
			continue
		}
		seen[key] = true

		sshPub, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			slog.Warn("could not convert CA cert to SSH public key",
				"subject", cert.Subject.String(), "err", err)
			continue
		}
		out = append(out, clusterCA{
			ControllerURL: urlRoot,
			AuthorizedKey: ssh.MarshalAuthorizedKey(sshPub),
		})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no intermediate CA public keys found across %d controller(s)", len(urlRoots))
	}
	return out, nil
}

// clusterCAsToBytes concatenates all authorized_key lines from cas into a
// single byte slice suitable for writing to TrustedUserCAKeys.
func clusterCAsToBytes(cas []clusterCA) []byte {
	var out []byte
	for _, ca := range cas {
		out = append(out, ca.AuthorizedKey...)
	}
	return out
}

// intCAFromController dials controllerURL over TLS and returns the intermediate
// CA certificate from the presented chain. The controller sends its leaf cert
// plus the signing intermediate CA in every TLS handshake; no HTTP request or
// authentication is needed.
//
// rootPool is used to validate the TLS connection. Pass nil during enrollment
// bootstrap (InsecureSkipVerify is used); pass the identity CA pool at runtime.
func intCAFromController(controllerURL string, rootPool *x509.CertPool) (*x509.Certificate, error) {
	u, err := url.Parse(controllerURL)
	if err != nil {
		return nil, fmt.Errorf("parse controller URL: %w", err)
	}

	host := u.Host
	if u.Port() == "" {
		host += ":443"
	}

	tlsConfig := &tls.Config{ServerName: u.Hostname()}
	if rootPool != nil {
		tlsConfig.RootCAs = rootPool
	} else {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // enrollment bootstrap — no pool yet
	}

	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS dial %q: %w", host, err)
	}
	state := conn.ConnectionState()
	conn.Close()

	for i, cert := range state.PeerCertificates {
		slog.Debug("TLS chain cert",
			"url", controllerURL,
			"index", i,
			"subject", cert.Subject.String(),
			"issuer", cert.Issuer.String(),
			"isCA", cert.IsCA,
			"selfSigned", cert.Subject.String() == cert.Issuer.String())
	}

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates in TLS chain from %q", host)
	}
	leaf := state.PeerCertificates[0]
	// Walk the chain and pick the cert whose Subject matches the leaf's Issuer
	// field. Raw-bytes comparison avoids encoding differences that string
	// formatting can obscure, and correctly identifies the signing intermediate
	// even when the chain contains cross-signed or multiple intermediate certs.
	for _, cert := range state.PeerCertificates[1:] {
		if cert.IsCA && bytes.Equal(cert.RawSubject, leaf.RawIssuer) {
			return cert, nil
		}
	}
	// Fallback to the original heuristic for unusual chain orderings.
	for _, cert := range state.PeerCertificates {
		if cert.IsCA && !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("no intermediate CA in TLS chain from %q", host)
}

// refreshTrustedCAs fetches the current set of intermediate CA public keys
// from the supplied controller URLs and updates TrustedUserCAKeys + reloads
// sshd if the set has changed. Logs only when the set changes (additions
// with controller URL, removals by count).
func refreshTrustedCAs(urls []*url.URL, rootPool *x509.CertPool) error {
	if len(urls) == 0 {
		return nil
	}
	urlStrs := make([]string, len(urls))
	for i, u := range urls {
		urlStrs[i] = u.String()
	}

	newCAs, err := collectClusterCAs(urlStrs, rootPool)
	if err != nil {
		return fmt.Errorf("collect CA public keys: %w", err)
	}
	newKeyBytes := clusterCAsToBytes(newCAs)

	current, err := os.ReadFile(sshdCAPubKeyFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %q: %w", sshdCAPubKeyFile, err)
	}

	if sshPubKeySetsEqual(current, newKeyBytes) {
		slog.Debug("trusted CA keys unchanged", "controllers", len(urls))
		return nil
	}

	// Log what changed before writing.
	oldSet := make(map[string]bool)
	for _, line := range nonEmptyLines(string(current)) {
		oldSet[normalizeSSHKey(line)] = true
	}
	newSet := make(map[string]bool)
	for _, ca := range newCAs {
		nk := normalizeSSHKey(strings.TrimSpace(string(ca.AuthorizedKey)))
		newSet[nk] = true
		if !oldSet[nk] {
			slog.Info("adding trusted CA for controller", "url", ca.ControllerURL)
		}
	}
	removedCount := 0
	for k := range oldSet {
		if !newSet[k] {
			removedCount++
		}
	}
	if removedCount > 0 {
		slog.Info("removing trusted CA(s) no longer in cluster", "count", removedCount)
	}

	// Write atomically: sshd may read the file at any time, and a
	// truncate-then-write window would leave it with an empty TrustedUserCAKeys,
	// causing cert auth to fail for connections that arrive during the write.
	tmp, err := os.CreateTemp(filepath.Dir(sshdCAPubKeyFile), ".ziti_ca_tmp_*")
	if err != nil {
		return fmt.Errorf("create temp CA key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeds
	if _, err := tmp.Write(newKeyBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp CA key file: %w", err)
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp CA key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp CA key file: %w", err)
	}
	if err := os.Rename(tmpName, sshdCAPubKeyFile); err != nil {
		return fmt.Errorf("rename temp CA key file to %q: %w", sshdCAPubKeyFile, err)
	}
	return host.ReloadSSHD()
}

// normalizeSSHKey returns the "type base64key" portion of an authorized_keys
// line for set-equality comparisons (ignores trailing comments).
func normalizeSSHKey(line string) string {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return parts[0] + " " + parts[1]
	}
	return line
}

// listClusterControllerURLs queries the active controller via the SDK's
// authenticated REST client for the current cluster member list. This is the
// same call the SDK makes internally in ProcessControllers, but ProcessControllers
// only runs at Authenticate and hourly session renewal — calling it here lets us
// detect newly added controllers without waiting.
//
// Returns edge-client v1 URLs (one per unique controller host).
func listClusterControllerURLs(zitiCtx ziti.Context) ([]*url.URL, error) {
	ctxImpl, ok := zitiCtx.(*ziti.ContextImpl)
	if !ok {
		return nil, fmt.Errorf("ziti context is not *ziti.ContextImpl; cannot list cluster controllers")
	}
	list, err := ctxImpl.CtrlClt.AuthEnabledApi.ListControllers()
	if err != nil {
		return nil, fmt.Errorf("list controllers: %w", err)
	}
	if list == nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	var urls []*url.URL
	for _, ctrl := range *list {
		addrs, ok := ctrl.APIAddresses["edge-client"]
		if !ok {
			continue
		}
		for _, addr := range addrs {
			if addr.Version != "v1" {
				continue
			}
			u, err := url.Parse(addr.URL)
			if err != nil || seen[u.Host] {
				continue
			}
			seen[u.Host] = true
			urls = append(urls, u)
		}
	}
	return urls, nil
}

// sshPubKeySetsEqual reports whether a and b contain the same set of SSH
// public key lines, regardless of order.
func sshPubKeySetsEqual(a, b []byte) bool {
	aLines := nonEmptyLines(string(a))
	bLines := nonEmptyLines(string(b))
	if len(aLines) != len(bLines) {
		return false
	}
	sortStrings(aLines)
	sortStrings(bLines)
	for i := range aLines {
		if aLines[i] != bLines[i] {
			return false
		}
	}
	return true
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
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
		if entry.SudoersRule != "" {
			if err := host.ValidateSudoersRule(entry.SudoersRule); err != nil {
				return nil, fmt.Errorf("service %q config: identity %q: %w", serviceName, identity, err)
			}
		}
		pc.Permissions[identity] = host.IdentityPermissions{
			Groups:      entry.Groups,
			SudoersRule: entry.SudoersRule,
		}
	}
	// Validate that no two explicit (non-glob) config keys derive to the same
	// Linux username. A collision allows one Ziti identity to connect as another
	// identity's Linux account, potentially inheriting elevated permissions.
	// Glob patterns are skipped — they match many identities and have no single
	// derived username. Runtime collision detection in UserManager.EnsureUser
	// handles the glob case.
	derived := make(map[string]string, len(pc.Permissions))
	var collisions []string
	for identity := range pc.Permissions {
		if strings.ContainsAny(identity, "*?") {
			continue
		}
		uname := ca.DeriveUsername(identity)
		if prev, exists := derived[uname]; exists {
			collisions = append(collisions, fmt.Sprintf("%q and %q both derive to %q", prev, identity, uname))
		} else {
			derived[uname] = identity
		}
	}
	if len(collisions) > 0 {
		return nil, fmt.Errorf("service %q config has username collisions (fix or remove one of each pair): %s",
			serviceName, strings.Join(collisions, "; "))
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
	// Load the Ziti config to build the CA pool used when refreshing trusted
	// CA keys after a controller cluster membership change.
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		return fmt.Errorf("load config from %q: %w", identityFile, err)
	}
	rootPool, err := buildCAPool(cfg)
	if err != nil {
		return fmt.Errorf("build CA pool: %w", err)
	}

	// Use NewConfigFromFile + NewContext so we can inject ConfigTypes before
	// the first Authenticate call.
	zitiCtx, err := newZitiContextWithConfigTypes(identityFile, zitiSSHHostConfigType)
	if err != nil {
		return fmt.Errorf("init Ziti context from %q: %w", identityFile, err)
	}
	defer zitiCtx.Close()

	// cachedCtrlURLs holds the most-recently-seen controller URL list so the
	// periodic poller can refresh TrustedUserCAKeys without waiting for the
	// hourly session renewal that triggers EventControllerUrlsUpdated.
	var (
		cachedMu       sync.Mutex
		cachedCtrlURLs []*url.URL
	)

	// Subscribe to controller URL updates BEFORE authenticating so that the
	// initial controller discovery during Authenticate is captured. When the
	// cluster gains or loses a node the event fires again, allowing
	// TrustedUserCAKeys to be updated without restarting the daemon.
	//
	// AddControllerUrlsUpdateListener is not part of the Eventer interface, so
	// we use the generic On() with a type assertion on the argument.
	zitiCtx.Events().On(ziti.EventControllerUrlsUpdated, func(args ...interface{}) {
		if len(args) == 0 {
			return
		}
		urls, ok := args[0].([]*url.URL)
		if !ok {
			return
		}
		cachedMu.Lock()
		cachedCtrlURLs = urls
		cachedMu.Unlock()

		// Persist the full controller list so future process starts can
		// bootstrap from any cluster member, not just the enrolled one.
		urlStrs := make([]string, len(urls))
		for i, u := range urls {
			urlStrs[i] = u.String()
		}
		if err := config.PersistZtAPIs(identityFile, urlStrs); err != nil {
			slog.Warn("failed to persist controller URLs to identity file", "err", err)
		}

		if err := refreshTrustedCAs(urls, rootPool); err != nil {
			slog.Error("failed to refresh trusted CA keys", "err", err)
		}
	})

	if err := config.RunWithTimeout(zitiTimeout, "authenticate", zitiCtx.Authenticate); err != nil {
		return err
	}

	// EventControllerUrlsUpdated only fires at Authenticate and at the hourly
	// session renewal. Poll the controller's /controllers endpoint directly on a
	// shorter interval so that newly added cluster members are trusted without
	// waiting up to an hour. Falls back to the cached URL list on error.
	const caPollInterval = 5 * time.Minute
	pollDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(caPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pollDone:
				return
			case <-ticker.C:
				urls, err := listClusterControllerURLs(zitiCtx)
				if err != nil {
					slog.Debug("failed to list cluster controllers, using cached URLs", "err", err)
					cachedMu.Lock()
					urls = cachedCtrlURLs
					cachedMu.Unlock()
				}
				if len(urls) == 0 {
					continue
				}
				if err := refreshTrustedCAs(urls, rootPool); err != nil {
					slog.Error("failed to poll trusted CA keys", "err", err)
				}
			}
		}
	}()

	// Global fallback permissions from environment variables.
	globalSudoersRule := os.Getenv("ZITI_SUDOERS_RULE")
	globalGroups := parseGlobalGroups()
	cleanupOnDisconnect := os.Getenv("ZITI_USER_CLEANUP") == "true"

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
					return mgr.EnsureUser(zitiIdentity, username, perms)
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
		// Restore default signal handling so a second SIGINT/SIGTERM exits
		// immediately if the drain hangs (instead of being silently swallowed
		// by the now-drained channel).
		signal.Reset(syscall.SIGTERM, syscall.SIGINT)
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
	close(pollDone) // stop the CA poll goroutine
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
