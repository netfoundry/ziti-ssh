// Package host provides utilities for the ziti-ssh-host daemon: proxying
// incoming Ziti connections to a local sshd, configuring sshd to trust
// the CA's public key, and managing ephemeral per-identity Linux users.
package host

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IdentityPermissions holds the resolved Linux permissions for a single
// connecting Ziti identity on a specific service.
type IdentityPermissions struct {
	// Groups is a list of existing Linux groups to add the ephemeral user to
	// via "usermod -aG" after account creation. Groups must already exist on
	// the host; a missing group causes a non-fatal logged error.
	Groups []string

	// SudoersRule is the rule fragment written after the username in
	// /etc/sudoers.d/<username>. An empty string means no sudoers file is
	// created for this user.
	SudoersRule string
}

// PermissionsConfig holds the parsed ziti-ssh-host.v1 service config. It maps
// exact Ziti identity names (case-sensitive) to their per-service permissions.
type PermissionsConfig struct {
	// Permissions maps Ziti identity name → IdentityPermissions.
	Permissions map[string]IdentityPermissions
}

// Resolve returns the effective IdentityPermissions for zitiIdentity.
//
// Resolution order:
//  1. Exact key match — zitiIdentity found as a literal key in the map.
//  2. Most specific glob pattern — among all map keys containing '*' or '?'
//     that match zitiIdentity (via path.Match), the winner is determined by
//     a two-field score: (prefixLen, totalLiterals) compared lexicographically
//     descending. prefixLen is the count of literal characters before the first
//     wildcard; totalLiterals is the count of all non-wildcard characters in
//     the pattern. This correctly ranks "*@dba" (0, 4) above "*" (0, 0).
//  3. Env var fallback — globalGroups / globalSudoersRule (unchanged).
//
// In all matching cases the matched entry is returned as-is; global
// fallbacks are not merged in.
func (pc *PermissionsConfig) Resolve(zitiIdentity string, globalGroups []string, globalSudoersRule string) IdentityPermissions {
	if pc != nil {
		// Step 1: exact match.
		if entry, ok := pc.Permissions[zitiIdentity]; ok {
			return entry
		}

		// Step 2: glob match — find the most specific pattern that matches.
		bestPrefixLen := -1
		bestTotalLiterals := 0
		var bestEntry IdentityPermissions
		for pattern, entry := range pc.Permissions {
			if !strings.ContainsAny(pattern, "*?") {
				// Pure literal key that didn't match exactly — skip.
				continue
			}
			matched, err := path.Match(pattern, zitiIdentity)
			if err != nil {
				// path.Match only errors on malformed patterns (unclosed '[').
				// Log and skip rather than crashing.
				slog.Warn("invalid glob pattern in permissions config, skipping",
					"pattern", pattern, "err", err)
				continue
			}
			if !matched {
				continue
			}
			pl, tl := patternSpecificity(pattern)
			if pl > bestPrefixLen || (pl == bestPrefixLen && tl > bestTotalLiterals) {
				bestPrefixLen = pl
				bestTotalLiterals = tl
				bestEntry = entry
			}
		}
		if bestPrefixLen >= 0 {
			return bestEntry
		}
	}

	// Step 3: env var fallback.
	return IdentityPermissions{
		Groups:      globalGroups,
		SudoersRule: globalSudoersRule,
	}
}

// patternSpecificity returns two counts for a glob pattern:
//   - prefixLen: the number of literal (non-wildcard) characters before the
//     first '*' or '?' in the pattern.
//   - totalLiterals: the total count of all non-wildcard characters in the
//     pattern (including those after wildcards).
//
// Both values are used together to rank competing glob patterns: a longer
// literal prefix wins outright; when prefixes are equal, more total literal
// characters indicate a more specific pattern (e.g. "*@dba" beats "*").
//
// Examples:
//
//	"alice@*"    → prefixLen=6, totalLiterals=6
//	"*@corp.com" → prefixLen=0, totalLiterals=9
//	"*@dba"      → prefixLen=0, totalLiterals=4
//	"*"          → prefixLen=0, totalLiterals=0
func patternSpecificity(pattern string) (prefixLen, totalLiterals int) {
	seenWildcard := false
	for _, ch := range pattern {
		if ch == '*' || ch == '?' {
			seenWildcard = true
			continue
		}
		totalLiterals++
		if !seenWildcard {
			prefixLen++
		}
	}
	return prefixLen, totalLiterals
}

// ProxyHooks carries optional callbacks for per-connection user lifecycle
// management. Both fields may be nil — pass a nil *ProxyHooks (or a
// ProxyHooks with nil fields) for shared mode where no user management is
// needed.
//
// OnConnect is called with the derived Linux username before proxying begins.
// If OnConnect returns a non-nil error the connection is closed without
// proxying.
//
// OnDisconnect is called with the derived Linux username after the connection
// closes, regardless of how it closed.
type ProxyHooks struct {
	OnConnect    func(username string) error
	OnDisconnect func(username string)
}

// Proxy accepts connections from listener and forwards each to target
// (e.g. "127.0.0.1:22") using bidirectional io.Copy. Each connection is
// handled in its own goroutine. Proxy blocks until listener.Accept fails,
// which is the normal shutdown path (caller closes the listener).
//
// hooks is optional. When non-nil and its fields are non-nil, OnConnect is
// called before proxying and OnDisconnect is called after. The username
// passed to the hooks is extracted from the connection via SourceIdentifier()
// (preferred) or GetDialerIdentityName() (fallback); if neither is available
// the hooks are skipped.
//
// wg is optional. When non-nil, each accepted connection increments wg before
// starting and decrements it when the connection closes. Pass a WaitGroup to
// enable graceful drain: after Proxy returns, call wg.Wait() (with a timeout
// of your choice) to block until all in-flight connections have finished.
func Proxy(listener net.Listener, target string, hooks *ProxyHooks, wg *sync.WaitGroup) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// listener was closed — normal shutdown
			slog.Info("proxy listener closed", "err", err)
			return
		}
		if wg != nil {
			wg.Add(1)
		}
		go func(c net.Conn) {
			if wg != nil {
				defer wg.Done()
			}
			proxyConn(c, target, hooks)
		}(conn)
	}
}

// callerName returns the Ziti identity name for the connection.
//
// The SDK sets CallerIdHeader to the dialer's identity name on every dial and
// exposes it via SourceIdentifier(). GetDialerIdentityName() reads a separate
// header injected by the fabric layer that may not be present. We prefer
// SourceIdentifier() and fall back to GetDialerIdentityName().
//
// Defined via structural interfaces so host has no import dependency on the
// Ziti SDK.
func callerName(conn net.Conn) string {
	type sourceIdentifier interface {
		SourceIdentifier() string
	}
	if si, ok := conn.(sourceIdentifier); ok {
		if name := si.SourceIdentifier(); name != "" {
			return name
		}
	}
	type dialerNamer interface {
		GetDialerIdentityName() string
	}
	if dn, ok := conn.(dialerNamer); ok {
		return dn.GetDialerIdentityName()
	}
	return ""
}

func proxyConn(src net.Conn, target string, hooks *ProxyHooks) {
	defer src.Close()

	// Resolve username for hooks, if any hook is registered.
	var username string
	if hooks != nil && (hooks.OnConnect != nil || hooks.OnDisconnect != nil) {
		username = callerName(src)
	}

	// OnConnect lifecycle — must succeed before we proxy anything.
	if hooks != nil && hooks.OnConnect != nil && username != "" {
		if err := hooks.OnConnect(username); err != nil {
			slog.Error("OnConnect hook failed", "username", username, "err", err)
			return
		}
	}

	// Ensure OnDisconnect always runs after this point.
	if hooks != nil && hooks.OnDisconnect != nil && username != "" {
		defer hooks.OnDisconnect(username)
	}

	dst, err := net.Dial("tcp", target)
	if err != nil {
		slog.Error("dial sshd failed", "target", target, "err", err)
		return
	}
	defer dst.Close()

	done := make(chan struct{}, 2)
	pipeCopy := func(w io.Writer, r io.Reader) {
		_, _ = io.Copy(w, r)
		done <- struct{}{}
	}

	go pipeCopy(dst, src)
	go pipeCopy(src, dst)

	// Wait for either direction to finish then let defers close both.
	<-done
}

// WriteSSHConfig writes the CA public key to keyFile (mode 0644) and writes
// a sshd_config.d snippet referencing it to confFile (mode 0644). Parent
// directories are created as needed.
//
// Example:
//
//	WriteSSHConfig(pubKeyBytes,
//	    "/etc/ssh/sshd_config.d/ziti-ssh.conf",
//	    "/etc/ssh/ziti_ca.pub")
func WriteSSHConfig(caPubKey []byte, confFile, keyFile string) error {
	// Write CA public key file atomically so sshd never sees a truncated file.
	if err := os.MkdirAll(filepath.Dir(keyFile), 0755); err != nil {
		return fmt.Errorf("create dir for %q: %w", keyFile, err)
	}
	if err := atomicWriteFile(keyFile, caPubKey, 0644); err != nil {
		return fmt.Errorf("write CA public key to %q: %w", keyFile, err)
	}

	// Write sshd drop-in config atomically.
	if err := os.MkdirAll(filepath.Dir(confFile), 0755); err != nil {
		return fmt.Errorf("create dir for %q: %w", confFile, err)
	}
	conf := fmt.Sprintf("TrustedUserCAKeys %s\n", keyFile)
	if err := atomicWriteFile(confFile, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write sshd config to %q: %w", confFile, err)
	}

	slog.Info("wrote sshd CA config", "conf", confFile, "key", keyFile)
	return nil
}

// atomicWriteFile writes data to a temp file in the same directory as dest,
// fsyncs, sets mode, renames over dest, then fsyncs the parent directory.
// A crash at any point leaves either the old or the new file fully intact.
func atomicWriteFile(dest string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Clean up the temp file on any error path.
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	// Fsync the parent directory so the rename is durable.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

// ReloadSSHD signals sshd to reload its configuration.
//
// Ubuntu 24.04 defaults to socket-activated sshd (ssh.socket + ssh@.service):
// each incoming connection spawns a fresh sshd that re-reads sshd_config at
// fork, so no daemon reload is required — the next connection automatically
// picks up TrustedUserCAKeys. When the traditional long-running ssh.service is
// active instead, SIGHUP is delivered via "systemctl reload ssh".
//
// In both cases pkill broadcasts SIGHUP to any top-level sshd listener
// processes (PPID=1) that may be co-listening via SO_REUSEPORT alongside the
// managed instance. This covers orphaned sshd parents left by service restarts
// during provisioning. Per-connection children call signal(SIGHUP, SIG_IGN)
// after privilege separation (OpenSSH 8.x+) and are unaffected.
func ReloadSSHD() error {
	// Validate configuration before reloading. sshd -t reads the full config
	// tree (including sshd_config.d drop-ins) and checks that referenced files
	// such as TrustedUserCAKeys exist and are well-formed. Failing here is
	// preferable to reloading with a broken config that locks out cert auth.
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("sshd config validation failed (not reloading): %w\n%s", err, strings.TrimSpace(string(out)))
	}

	// Detect socket-activated sshd (Ubuntu 24.04 default). Under socket
	// activation, ssh.service is typically masked and "systemctl reload ssh"
	// would fail — but no reload is needed because each sshd instance reads
	// its config at fork time.
	socketActive := exec.Command("systemctl", "is-active", "--quiet", "ssh.socket").Run() == nil
	if socketActive {
		slog.Info("sshd is socket-activated; new connections will pick up TrustedUserCAKeys automatically")
	} else {
		cmd := exec.Command("systemctl", "reload", "ssh")
		cmd.Env = childEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl reload ssh: %w (output: %s)", err, out)
		}
	}

	// Under ssh.service (non-socket), also signal any top-level sshd listener
	// that may have been spawned outside systemd. Skip this under socket
	// activation: per-connection sshd children have PPID 1 there too, and
	// sending SIGHUP to an active connection sshd disconnects the session.
	if !socketActive {
		if err := exec.Command("pkill", "-HUP", "-P", "1", "-x", "sshd").Run(); err != nil {
			slog.Debug("pkill sshd: no additional listener processes to signal", "err", err)
		}
	}

	slog.Info("sshd reloaded")
	return nil
}

// childEnv returns the current process environment with NOTIFY_SOCKET removed.
// Child processes must not inherit this variable — systemd rejects sd_notify
// messages from any PID other than the registered main PID of the service.
func childEnv() []string {
	env := os.Environ()
	filtered := env[:0:len(env)]
	for _, e := range env {
		if !strings.HasPrefix(e, "NOTIFY_SOCKET=") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// UserManager tracks reference counts for per-identity Linux users and
// persists the set of managed usernames to a state file so that orphaned
// users created before a crash can be cleaned up on the next startup.
//
// All exported methods are safe for concurrent use.
type UserManager struct {
	mu                  sync.Mutex
	sessions            map[string]int    // username → active session count
	owners              map[string]string // username → Ziti identity that created the account
	userLocks           map[string]*sync.Mutex // username → per-user lock for slow OS ops
	stateFile           string
	cleanupOnDisconnect bool // if false, skip deleteUser on ReleaseUser
}

// NewUserManager returns a UserManager that persists state to stateFile.
// The state file and its parent directories are created on first write.
//
// cleanupOnDisconnect controls whether the Linux user is deleted when the last
// session closes. When false, the account persists across disconnects; the
// sudoers file is still removed if one was written.
func NewUserManager(stateFile string, cleanupOnDisconnect bool) *UserManager {
	return &UserManager{
		sessions:            make(map[string]int),
		owners:              make(map[string]string),
		userLocks:           make(map[string]*sync.Mutex),
		stateFile:           stateFile,
		cleanupOnDisconnect: cleanupOnDisconnect,
	}
}

// EnsureUser creates the Linux user if this is the first session for that
// username. zitiIdentity is the caller's Ziti identity name; username is its
// derived Linux username (from ca.DeriveUsername). The pair is recorded so
// that if a different Ziti identity later derives the same Linux username the
// connection is rejected rather than silently inheriting the first caller's
// permissions.
//
// useradd is called with "-m -s /bin/bash <username>". If useradd reports
// that the user already exists (exit code 9) the error is ignored so that
// concurrent connections that race to create the same user are handled
// gracefully.
//
// perms carries the resolved per-identity permissions for this connection.
// Groups and sudoers are only applied on the first session for a username
// (when the account is actually created). Subsequent sessions for the same
// username log a message and return immediately.
//
// The username is recorded in the state file so that CleanupOrphans can
// remove it after a crash.
func (m *UserManager) EnsureUser(zitiIdentity, username string, perms IdentityPermissions) error {
	// Phase 1 (global lock, fast): ownership check, session bookkeeping, and
	// per-user lock acquisition. No blocking OS calls are made here.
	m.mu.Lock()
	if owner, owned := m.owners[username]; owned && owner != zitiIdentity {
		m.mu.Unlock()
		return fmt.Errorf("username %q (derived from %q) is already in use by Ziti identity %q: connection rejected to prevent privilege collision",
			username, zitiIdentity, owner)
	}
	m.sessions[username]++
	isFirst := m.sessions[username] == 1
	if isFirst {
		// Record ownership atomically with the session increment so there is no
		// window where the account exists without a recorded owner.
		m.owners[username] = zitiIdentity
	}
	ul, ok := m.userLocks[username]
	if !ok {
		ul = &sync.Mutex{}
		m.userLocks[username] = ul
	}
	m.mu.Unlock()

	if !isFirst {
		// Acquire the per-user lock to:
		//   (a) wait for the first caller to finish useradd before proceeding
		//       (H5 barrier — prevents SSH login before /etc/passwd is written), and
		//   (b) re-apply permissions idempotently, so a config change takes effect
		//       on the next concurrent session without waiting for all sessions to
		//       close (C2 fix — "regardless of session count").
		//
		// Invariant: by the time EnsureUser returns nil, the Linux user exists in
		// /etc/passwd (or useradd reported it already existed).
		ul.Lock()
		defer ul.Unlock()

		slog.Info("user already exists, re-applying permissions", "username", username, "sessions", m.sessions[username])

		groupList := strings.Join(perms.Groups, ",")
		slog.Info("setting user supplementary groups", "username", username, "groups", groupList)
		usermod := exec.Command("usermod", "-G", groupList, username)
		usermod.Env = childEnv()
		if out, err := usermod.CombinedOutput(); err != nil {
			slog.Error("usermod -G failed", "username", username, "groups", groupList, "err", err, "output", strings.TrimSpace(string(out)))
		}

		if perms.SudoersRule != "" {
			if err := createSudoers(username, perms.SudoersRule); err != nil {
				slog.Error("failed to update sudoers file", "username", username, "err", err)
			}
		} else {
			// Config no longer specifies a sudoers rule — remove any stale file.
			if err := removeSudoers(username); err != nil {
				slog.Error("failed to remove stale sudoers file", "username", username, "err", err)
			}
		}

		return nil
	}

	// Phase 2 (per-user lock only): slow OS operations. The global lock is not
	// held here, so other usernames proceed concurrently.
	ul.Lock()
	defer ul.Unlock()

	slog.Info("creating Linux user", "username", username)
	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		// useradd exits with code 9 when the user already exists.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 9 {
			slog.Info("user already exists, treating as success", "username", username, "ziti_identity", zitiIdentity)
		} else {
			// Rollback: undo the session increment and ownership record.
			m.mu.Lock()
			m.sessions[username]--
			if m.sessions[username] == 0 {
				delete(m.sessions, username)
				delete(m.owners, username)
			}
			m.mu.Unlock()
			return fmt.Errorf("useradd %q: %w (output: %s)", username, err, out)
		}
	}

	// Set the user's supplementary groups to exactly the configured list.
	// -G replaces the full supplementary group membership rather than
	// appending (-aG), so revocations take effect on the next reconnect
	// without needing to delete and recreate the account. An empty list
	// clears all supplementary groups.
	groupList := strings.Join(perms.Groups, ",")
	slog.Info("setting user supplementary groups", "username", username, "groups", groupList)
	usermod := exec.Command("usermod", "-G", groupList, username)
	usermod.Env = childEnv()
	if out, err := usermod.CombinedOutput(); err != nil {
		// Non-fatal: the user was created successfully; group membership
		// failure (e.g. group does not exist) is logged but does not abort
		// the session.
		slog.Error("usermod -G failed", "username", username, "groups", groupList, "err", err, "output", strings.TrimSpace(string(out)))
	}

	// Write sudoers file if a rule is configured.
	if perms.SudoersRule != "" {
		if err := createSudoers(username, perms.SudoersRule); err != nil {
			// Non-fatal: the user was created successfully; sudoers failure
			// should not block the session, but it must be visible in logs.
			slog.Error("failed to create sudoers file", "username", username, "err", err)
		}
	}

	// Persist the username so orphan cleanup can find it after a restart.
	if err := m.syncStateFile(); err != nil {
		slog.Error("failed to write state file", "username", username, "err", err)
		// Non-fatal: the user was created; orphan cleanup may miss it after a
		// crash, but the session ref-count is correct for this run.
	}

	return nil
}

// ReleaseUser decrements the session count for username. When the count
// reaches zero, the Linux user is deleted with "userdel -r <username>" and
// the username is removed from the state file.
func (m *UserManager) ReleaseUser(username string) error {
	// Phase 1 (global lock, fast): session bookkeeping only.
	m.mu.Lock()
	if m.sessions[username] <= 0 {
		m.mu.Unlock()
		return fmt.Errorf("ReleaseUser called for untracked username %q: indicates a session accounting bug", username)
	}
	m.sessions[username]--
	if m.sessions[username] > 0 {
		remaining := m.sessions[username]
		m.mu.Unlock()
		slog.Info("session released, user still active", "username", username, "sessions", remaining)
		return nil
	}
	delete(m.sessions, username)
	delete(m.owners, username)
	ul := m.userLocks[username]
	m.mu.Unlock()

	// Phase 2 (per-user lock only): slow OS operations. The global lock is not
	// held here, so other usernames proceed concurrently.
	if ul != nil {
		ul.Lock()
		defer ul.Unlock()
	}

	if !m.cleanupOnDisconnect {
		slog.Info("last session closed, cleanup disabled — keeping Linux user", "username", username)
		// Always attempt to remove the sudoers file (it may or may not exist).
		// removeSudoers is a no-op if the file is absent.
		if err := removeSudoers(username); err != nil {
			slog.Error("failed to remove sudoers file", "username", username, "err", err)
		}
		if err := m.syncStateFile(); err != nil {
			slog.Error("failed to update state file", "username", username, "err", err)
		}
		return nil
	}

	slog.Info("last session closed, deleting Linux user", "username", username)
	if err := deleteUser(username); err != nil {
		return err
	}

	if err := m.syncStateFile(); err != nil {
		slog.Error("failed to update state file after deletion", "username", username, "err", err)
		// Non-fatal.
	}

	return nil
}

// CleanupOrphans reads the state file and calls userdel -r on each listed
// username. It is intended to be called at startup, before accepting any
// connections, to remove users that were not cleaned up after a crash.
//
// Errors deleting individual users are logged but do not stop cleanup of the
// remaining users.
func (m *UserManager) CleanupOrphans() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.stateFile)
	if os.IsNotExist(err) {
		// No state file — nothing to clean up.
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state file %q: %w", m.stateFile, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var remaining []string

	for scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		if username == "" {
			continue
		}
		if !m.cleanupOnDisconnect {
			// Users are intentionally persistent; do not delete them on
			// restart. Clear the state file so they are no longer tracked
			// by this process instance — they will not be cleaned up on the
			// next restart either, which is the correct behaviour.
			slog.Info("cleanup disabled; skipping orphan user deletion on restart", "username", username)
			continue
		}
		slog.Info("cleaning up orphan user", "username", username)
		if err := deleteUser(username); err != nil {
			slog.Error("failed to delete orphan user", "username", username, "err", err)
			// Keep in remaining so we try again on the next restart.
			remaining = append(remaining, username)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan state file: %w", err)
	}

	// Rewrite the state file with only the users we failed to delete.
	return m.writeStateFile(remaining)
}

// ValidateSudoersRule checks that rule is safe to embed in a sudoers file as
// the fragment following a username:
//
//	<username> <rule>\n
//
// Rejected values:
//   - newlines or carriage returns — a second line can grant permissions to
//     users other than the target, and visudo accepts multi-line files
//   - a leading '#' — sudo treats #include / #includedir as include directives
//     even inside files sourced via #includedir; a bare '#' also starts a
//     comment that terminates the effective rule
//   - known sudoers keywords (@include, Defaults, *_Alias) — these are valid
//     sudoers directives that must not appear as rule fragments
func ValidateSudoersRule(rule string) error {
	if strings.ContainsAny(rule, "\n\r") {
		return fmt.Errorf("sudoers_rule must not contain newlines")
	}
	trimmed := strings.TrimSpace(rule)
	if strings.HasPrefix(trimmed, "#") {
		return fmt.Errorf("sudoers_rule must not start with '#'")
	}
	for _, kw := range []string{"@include", "Defaults", "Cmnd_Alias", "Host_Alias", "User_Alias", "Runas_Alias"} {
		if strings.HasPrefix(trimmed, kw) {
			return fmt.Errorf("sudoers_rule must not start with %q", kw)
		}
	}
	return nil
}

// sudoersStagingDir is a hidden subdirectory inside /etc/sudoers.d used as a
// staging area for new sudoers files. sudo's #includedir directive only reads
// regular files — subdirectories are skipped — so temp files here are never
// parsed by sudo. The leading dot is an additional exclusion. Staging inside
// /etc/sudoers.d guarantees the final os.Rename is atomic (same filesystem).
const sudoersStagingDir = "/etc/sudoers.d/.ziti-ssh-host-staging"

// createSudoers writes a validated sudoers file to /etc/sudoers.d/<username>.
//
// The file content is "<username> <rule>\n". It is staged in sudoersStagingDir
// (a hidden subdirectory of /etc/sudoers.d that sudo ignores), validated with
// "visudo -c -f", then atomically renamed into place at mode 0440.
func createSudoers(username, rule string) error {
	if err := ValidateSudoersRule(rule); err != nil {
		return fmt.Errorf("invalid sudoers rule for %q: %w", username, err)
	}
	content := fmt.Sprintf("%s %s\n", username, rule)

	// Stage outside the active include path so sudo never parses the temp file.
	if err := os.MkdirAll(sudoersStagingDir, 0700); err != nil {
		return fmt.Errorf("create sudoers staging dir: %w", err)
	}
	tmp, err := os.CreateTemp(sudoersStagingDir, "sudoers-"+username+"-*")
	if err != nil {
		return fmt.Errorf("create sudoers temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write sudoers temp file: %w", err)
	}
	tmp.Close()

	// chmod before visudo so validation runs with the permissions sudo sees.
	if err := os.Chmod(tmpPath, 0440); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod sudoers temp file: %w", err)
	}

	// visudo -c -f validates syntax without installing the file.
	visudo := exec.Command("visudo", "-c", "-f", tmpPath)
	visudo.Env = childEnv()
	if out, err := visudo.CombinedOutput(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("visudo validation failed for %q: %w (output: %s)", username, err, out)
	}

	// Atomic rename — same filesystem as the staging dir.
	dest := "/etc/sudoers.d/" + username
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("install sudoers file to %q: %w", dest, err)
	}

	slog.Info("created sudoers file", "username", username, "path", dest)
	return nil
}

// removeSudoers removes /etc/sudoers.d/<username> if it exists.
// A missing file is not treated as an error.
func removeSudoers(username string) error {
	path := "/etc/sudoers.d/" + username
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove sudoers file %q: %w", path, err)
	}
	return nil
}

// deleteUser drains the user's systemd session, waits for all owned processes
// to exit, then removes the user and their home directory with userdel -r.
// userProcessesGone polls pgrep until no processes owned by username remain or
// the timeout elapses. Returns true when the user has no remaining processes.
func userProcessesGone(username string, timeout time.Duration) bool {
	const pollInterval = 200 * time.Millisecond
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pgrep := exec.Command("pgrep", "-u", username)
		pgrep.Env = childEnv()
		err := pgrep.Run()
		if err != nil {
			// pgrep exits 1 when no processes match — user is clear.
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				return true
			}
			// Unexpected pgrep error (e.g. command not found) — stop polling.
			slog.Warn("pgrep error while waiting for user processes to exit",
				"username", username, "err", err)
			return false
		}
		time.Sleep(pollInterval)
	}
	return false
}

func deleteUser(username string) error {
	// Remove the sudoers file before tearing down the account.
	if err := removeSudoers(username); err != nil {
		slog.Error("failed to remove sudoers file during deleteUser", "username", username, "err", err)
		// Non-fatal: proceed with userdel regardless.
	}

	// Step 1: ask loginctl to terminate the user session (systemd --user,
	// sd-pam, etc.).  Ignore errors — the session may already be gone.
	loginctl := exec.Command("loginctl", "terminate-user", username)
	loginctl.Env = childEnv()
	if out, err := loginctl.CombinedOutput(); err != nil {
		slog.Info("loginctl terminate-user returned non-zero (ignored)",
			"username", username, "err", err, "output", strings.TrimSpace(string(out)))
	}

	// Step 2: wait up to 5 s for session processes to exit naturally.
	if !userProcessesGone(username, 5*time.Second) {
		// Step 3: escalate to SIGTERM for detached processes (nohup, screen,
		// tmux) that loginctl does not reach.
		slog.Info("user processes still running after loginctl; sending SIGTERM", "username", username)
		pkillTerm := exec.Command("pkill", "-TERM", "-u", username)
		pkillTerm.Env = childEnv()
		if out, err := pkillTerm.CombinedOutput(); err != nil {
			slog.Info("pkill -TERM returned non-zero (ignored)",
				"username", username, "err", err, "output", strings.TrimSpace(string(out)))
		}

		// Step 4: wait up to 10 s for SIGTERM to take effect.
		if !userProcessesGone(username, 10*time.Second) {
			// Step 5: escalate to SIGKILL — cannot be caught or ignored.
			slog.Warn("user processes still running after SIGTERM; sending SIGKILL", "username", username)
			pkillKill := exec.Command("pkill", "-KILL", "-u", username)
			pkillKill.Env = childEnv()
			if out, err := pkillKill.CombinedOutput(); err != nil {
				slog.Info("pkill -KILL returned non-zero (ignored)",
					"username", username, "err", err, "output", strings.TrimSpace(string(out)))
			}

			// Step 6: wait up to 5 s for the kernel to reap SIGKILL'd processes.
			if !userProcessesGone(username, 5*time.Second) {
				slog.Warn("user processes still running after SIGKILL; proceeding with userdel",
					"username", username)
			}
		}
	}

	// Step 7: remove the user and their home directory.
	cmd := exec.Command("userdel", "-r", username)
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 8 {
			// Exit code 8: user still has running processes. The account and
			// home directory were NOT deleted. The caller should retry after
			// the processes exit.
			return fmt.Errorf("userdel %q: user still has running processes; account not deleted (exit 8): %s",
				username, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("userdel -r %q: %w (output: %s)", username, err, out)
	}
	slog.Info("deleted Linux user", "username", username)
	return nil
}

// syncStateFile atomically rewrites the state file from the current contents
// of m.sessions. It briefly acquires m.mu to take a consistent snapshot, then
// releases it before performing file I/O — so callers must not hold m.mu.
//
// This replaces both the old addToStateFile (append) and removeFromStateFile
// (read-filter-rewrite) with a single always-correct snapshot: the in-memory
// sessions map is the source of truth, so there is no need to read the file
// and no risk of divergence between the file and the map.
func (m *UserManager) syncStateFile() error {
	m.mu.Lock()
	lines := make([]string, 0, len(m.sessions))
	for username := range m.sessions {
		lines = append(lines, username)
	}
	m.mu.Unlock()
	return m.writeStateFile(lines)
}

// writeStateFile atomically replaces the state file with lines.
// It writes to a temp file in the same directory, fsyncs, renames, then
// fsyncs the parent directory — so a crash at any point leaves either the old
// or the new file fully intact, never a zero-length or partially-written file.
func (m *UserManager) writeStateFile(lines []string) error {
	dir := filepath.Dir(m.stateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state file dir: %w", err)
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	tmp, err := os.CreateTemp(dir, ".managed-users-tmp-*")
	if err != nil {
		return fmt.Errorf("create state file temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write state file temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync state file temp: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod state file temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close state file temp: %w", err)
	}
	if err := os.Rename(tmpPath, m.stateFile); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename state file: %w", err)
	}
	// Fsync the parent directory to make the rename durable across power loss.
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		dirF.Close()
	}
	return nil
}
