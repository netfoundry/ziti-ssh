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
//  1. If pc is non-nil and zitiIdentity has an entry → return that entry
//     as-is. Global fallbacks are not merged in.
//  2. Otherwise → return global fallbacks (globalGroups, globalSudoersRule).
func (pc *PermissionsConfig) Resolve(zitiIdentity string, globalGroups []string, globalSudoersRule string) IdentityPermissions {
	if pc != nil {
		if entry, ok := pc.Permissions[zitiIdentity]; ok {
			return entry
		}
	}
	return IdentityPermissions{
		Groups:      globalGroups,
		SudoersRule: globalSudoersRule,
	}
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
	copy := func(w io.Writer, r io.Reader) {
		_, _ = io.Copy(w, r)
		done <- struct{}{}
	}

	go copy(dst, src)
	go copy(src, dst)

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
	// Write CA public key file.
	if err := os.MkdirAll(filepath.Dir(keyFile), 0755); err != nil {
		return fmt.Errorf("create dir for %q: %w", keyFile, err)
	}
	if err := os.WriteFile(keyFile, caPubKey, 0644); err != nil {
		return fmt.Errorf("write CA public key to %q: %w", keyFile, err)
	}

	// Write sshd drop-in config.
	if err := os.MkdirAll(filepath.Dir(confFile), 0755); err != nil {
		return fmt.Errorf("create dir for %q: %w", confFile, err)
	}
	conf := fmt.Sprintf("TrustedUserCAKeys %s\n", keyFile)
	if err := os.WriteFile(confFile, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write sshd config to %q: %w", confFile, err)
	}

	slog.Info("wrote sshd CA config", "conf", confFile, "key", keyFile)
	return nil
}

// ReloadSSHD signals sshd to reload its configuration by running
// "systemctl reload ssh". Returns an error if the command exits non-zero.
func ReloadSSHD() error {
	cmd := exec.Command("systemctl", "reload", "ssh")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl reload ssh: %w (output: %s)", err, out)
	}
	slog.Info("sshd reloaded")
	return nil
}

// UserManager tracks reference counts for per-identity Linux users and
// persists the set of managed usernames to a state file so that orphaned
// users created before a crash can be cleaned up on the next startup.
//
// All exported methods are safe for concurrent use.
type UserManager struct {
	mu                  sync.Mutex
	sessions            map[string]int // username → active session count
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
		stateFile:           stateFile,
		cleanupOnDisconnect: cleanupOnDisconnect,
	}
}

// EnsureUser creates the Linux user if this is the first session for that
// username. useradd is called with "-m -s /bin/bash <username>". If useradd
// reports that the user already exists (exit code 9) the error is ignored so
// that concurrent connections that race to create the same user are handled
// gracefully.
//
// perms carries the resolved per-identity permissions for this connection.
// Groups and sudoers are only applied on the first session for a username
// (when the account is actually created). Subsequent sessions for the same
// username log a message and return immediately.
//
// The username is recorded in the state file so that CleanupOrphans can
// remove it after a crash.
func (m *UserManager) EnsureUser(username string, perms IdentityPermissions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[username]++

	// Only run useradd on the first session for this username.
	if m.sessions[username] > 1 {
		slog.Info("user already tracked, skipping useradd", "username", username, "sessions", m.sessions[username])
		return nil
	}

	slog.Info("creating Linux user", "username", username)
	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// useradd exits with code 9 when the user already exists.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 9 {
			slog.Info("user already exists, treating as success", "username", username)
		} else {
			// Undo the session increment — the user was not created.
			m.sessions[username]--
			if m.sessions[username] == 0 {
				delete(m.sessions, username)
			}
			return fmt.Errorf("useradd %q: %w (output: %s)", username, err, out)
		}
	}

	// Add the user to supplementary groups if any are specified.
	if len(perms.Groups) > 0 {
		groupList := strings.Join(perms.Groups, ",")
		slog.Info("adding user to groups", "username", username, "groups", groupList)
		if out, err := exec.Command("usermod", "-aG", groupList, username).CombinedOutput(); err != nil {
			// Non-fatal: the user was created successfully; group membership
			// failure (e.g. group does not exist) is logged but does not abort
			// the session.
			slog.Error("usermod -aG failed", "username", username, "groups", groupList, "err", err, "output", strings.TrimSpace(string(out)))
		}
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
	if err := m.addToStateFile(username); err != nil {
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
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sessions[username] <= 0 {
		slog.Warn("ReleaseUser called for untracked username", "username", username)
		return nil
	}

	m.sessions[username]--
	if m.sessions[username] > 0 {
		slog.Info("session released, user still active", "username", username, "sessions", m.sessions[username])
		return nil
	}

	delete(m.sessions, username)

	if !m.cleanupOnDisconnect {
		slog.Info("last session closed, cleanup disabled — keeping Linux user", "username", username)
		// Always attempt to remove the sudoers file (it may or may not exist).
		// removeSudoers is a no-op if the file is absent.
		if err := removeSudoers(username); err != nil {
			slog.Error("failed to remove sudoers file", "username", username, "err", err)
		}
		if err := m.removeFromStateFile(username); err != nil {
			slog.Error("failed to update state file", "username", username, "err", err)
		}
		return nil
	}

	slog.Info("last session closed, deleting Linux user", "username", username)
	if err := deleteUser(username); err != nil {
		return err
	}

	if err := m.removeFromStateFile(username); err != nil {
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

// createSudoers writes a validated sudoers file to /etc/sudoers.d/<username>.
//
// The file content is "<username> <rule>\n". The rule is validated by running
// "visudo -c -f <tempfile>" before the file is moved into place. On validation
// failure the temp file is removed and an error is returned. On success the
// file is placed at /etc/sudoers.d/<username> with mode 0440.
func createSudoers(username, rule string) error {
	content := fmt.Sprintf("%s %s\n", username, rule)

	// Write to a temp file first so we can validate before installing.
	tmp, err := os.CreateTemp("/etc/sudoers.d", "sudoers-"+username+"-*")
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

	// visudo -c -f validates the file syntax without installing it.
	if out, err := exec.Command("visudo", "-c", "-f", tmpPath).CombinedOutput(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("visudo validation failed for %q: %w (output: %s)", username, err, out)
	}

	dest := "/etc/sudoers.d/" + username

	// Set mode 0440 before moving into place.
	if err := os.Chmod(tmpPath, 0440); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod sudoers temp file: %w", err)
	}

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
func deleteUser(username string) error {
	// Remove the sudoers file before tearing down the account.
	if err := removeSudoers(username); err != nil {
		slog.Error("failed to remove sudoers file during deleteUser", "username", username, "err", err)
		// Non-fatal: proceed with userdel regardless.
	}

	// Step 1: ask loginctl to terminate the user session (systemd --user,
	// sd-pam, etc.).  Ignore errors — the session may already be gone.
	if out, err := exec.Command("loginctl", "terminate-user", username).CombinedOutput(); err != nil {
		slog.Info("loginctl terminate-user returned non-zero (ignored)",
			"username", username, "err", err, "output", strings.TrimSpace(string(out)))
	}

	// Step 2: poll until no processes owned by the user remain, or timeout.
	const (
		pollInterval = 200 * time.Millisecond
		pollTimeout  = 5 * time.Second
	)
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		err := exec.Command("pgrep", "-u", username).Run()
		if err != nil {
			// pgrep exits 1 when no processes match — user is clear.
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				break
			}
			// Any other error from pgrep (e.g. command not found) — stop
			// polling and proceed; userdel will surface the real problem.
			slog.Warn("pgrep error while waiting for user processes to exit",
				"username", username, "err", err)
			break
		}
		// pgrep exited 0 — processes still exist; wait and retry.
		time.Sleep(pollInterval)
	}
	if !time.Now().Before(deadline) {
		slog.Warn("timed out waiting for user processes to exit, proceeding with userdel",
			"username", username, "timeout", pollTimeout)
	}

	// Step 3: remove the user and their home directory.
	cmd := exec.Command("userdel", "-r", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("userdel -r %q: %w (output: %s)", username, err, out)
	}
	slog.Info("deleted Linux user", "username", username)
	return nil
}

// addToStateFile appends username to the state file (one entry per line).
// Parent directories are created as needed.
func (m *UserManager) addToStateFile(username string) error {
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0755); err != nil {
		return fmt.Errorf("create state file dir: %w", err)
	}
	f, err := os.OpenFile(m.stateFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open state file %q: %w", m.stateFile, err)
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, username)
	return err
}

// removeFromStateFile rewrites the state file omitting username.
func (m *UserManager) removeFromStateFile(username string) error {
	data, err := os.ReadFile(m.stateFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state file %q: %w", m.stateFile, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var keep []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != username {
			keep = append(keep, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan state file: %w", err)
	}

	return m.writeStateFile(keep)
}

// writeStateFile atomically replaces the state file contents with lines.
func (m *UserManager) writeStateFile(lines []string) error {
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0755); err != nil {
		return fmt.Errorf("create state file dir: %w", err)
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return os.WriteFile(m.stateFile, []byte(content), 0644)
}
