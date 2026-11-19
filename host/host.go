/*
    Copyright NetFoundry Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

// Package host provides utilities for the ziti-ssh-host daemon: proxying
// incoming Ziti connections to a local sshd, configuring sshd to trust
// the CA's public key, and managing ephemeral per-identity Linux users.
package host

import (
	"bufio"
	"errors"
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
	// Groups is the exact list of supplementary Linux groups for the user, set
	// via "usermod -G" on every connect. Groups must already exist on the host;
	// a missing group causes a non-fatal logged error.
	Groups []string

	// SudoersRule is the rule fragment written after the username in
	// SudoersPath(username). An empty string means no sudoers file is
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
// passed to the hooks is the router-verified dialer identity
// (GetDialerIdentityName()); if it is unavailable while hooks are configured,
// the connection is closed without proxying.
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

// callerName returns the router-verified Ziti identity name of the dialer.
//
// Only GetDialerIdentityName() is trusted. That header is set by the dialer's
// edge router (OpenZiti v2.0.0+) from the router's own record of the
// authenticated identity. SourceIdentifier() (the CallerId header) is written
// by the dialing SDK and copied through the router unchanged, so a modified
// client can claim any name; it is used only to log a warning on mismatch.
//
// Returns "" when the router did not supply a dialer identity.
//
// Defined via structural interfaces so host has no import dependency on the
// Ziti SDK.
func callerName(conn net.Conn) string {
	type dialerNamer interface {
		GetDialerIdentityName() string
	}
	dn, ok := conn.(dialerNamer)
	if !ok {
		return ""
	}
	name := dn.GetDialerIdentityName()

	type sourceIdentifier interface {
		SourceIdentifier() string
	}
	if si, ok := conn.(sourceIdentifier); ok {
		if claimed := si.SourceIdentifier(); claimed != "" && name != "" && claimed != name {
			slog.Warn("client-supplied caller id does not match router-verified dialer identity; using router-verified identity",
				"dialer_identity", name, "claimed_caller_id", claimed)
		}
	}
	return name
}

func proxyConn(src net.Conn, target string, hooks *ProxyHooks) {
	defer src.Close()

	// Resolve username for hooks, if any hook is registered.
	var username string
	if hooks != nil && (hooks.OnConnect != nil || hooks.OnDisconnect != nil) {
		username = callerName(src)
		// Fail closed: with hooks configured (per-identity mode) a connection
		// must never reach sshd without a router-verified identity.
		if username == "" {
			slog.Error("rejected connection: edge router did not supply a dialer identity (OpenZiti v2.0.0+ routers required)")
			return
		}
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

// UserManager tracks reference counts for per-identity Linux users and decides
// which accounts ziti-ssh-host is allowed to create, modify, and delete.
//
// Ownership is recorded in a persistent OwnerRegistry (owned-users.json, next
// to the state file). An account is managed only if it is in the registry for
// the connecting Ziti identity with a matching UID. Pre-existing accounts that
// ziti-ssh-host did not create — root, the distribution's default user, any
// administrator account — are never adopted, modified, or deleted.
//
// The managed-users state file separately lists accounts with active sessions
// so that CleanupOrphans can delete them after a crash (cleanup mode only).
//
// All exported methods are safe for concurrent use.
type UserManager struct {
	mu                  sync.Mutex
	sessions            map[string]int         // username → active session count
	userLocks           map[string]*sync.Mutex // username → per-user lock for slow OS ops
	stateFile           string
	registry            *OwnerRegistry
	ops                 accountOps
	cleanupOnDisconnect bool // if false, keep the account on ReleaseUser
}

// NewUserManager returns a UserManager that persists active sessions to
// stateFile and account ownership to OwnedUsersFileName in the same directory.
//
// cleanupOnDisconnect controls whether the Linux user is deleted when the last
// session closes. When false, the account persists across disconnects; the
// sudoers file is still removed if one was written.
//
// It returns an error if the ownership registry exists but cannot be read, so
// the daemon fails closed rather than managing accounts without it.
func NewUserManager(stateFile string, cleanupOnDisconnect bool) (*UserManager, error) {
	reg := NewOwnerRegistry(filepath.Join(filepath.Dir(stateFile), OwnedUsersFileName))
	if _, _, err := reg.List(); err != nil {
		return nil, err
	}
	return newUserManager(stateFile, reg, osAccountOps{}, cleanupOnDisconnect), nil
}

func newUserManager(stateFile string, reg *OwnerRegistry, ops accountOps, cleanupOnDisconnect bool) *UserManager {
	return &UserManager{
		sessions:            make(map[string]int),
		userLocks:           make(map[string]*sync.Mutex),
		stateFile:           stateFile,
		registry:            reg,
		ops:                 ops,
		cleanupOnDisconnect: cleanupOnDisconnect,
	}
}

// Registry returns the manager's ownership registry.
func (m *UserManager) Registry() *OwnerRegistry { return m.registry }

// EnsureUser prepares the Linux account for a new session of zitiIdentity,
// whose derived Linux username is username, and applies perms.
//
// The account is used only if one of the following holds:
//   - it does not exist: it is created with useradd, its UID is verified to be
//     >= MinManagedUID, and ownership is recorded in the registry; or
//   - it exists and the registry records it as owned by zitiIdentity with the
//     same UID.
//
// Every other case is rejected without touching the account: a pre-existing
// account not created by ziti-ssh-host, an account owned by a different Ziti
// identity (derived-username collision), an account deleted and recreated
// with a different UID, a UID below MinManagedUID, or a reserved/invalid name.
//
// On success, supplementary groups are set to exactly perms.Groups and the
// sudoers file is written (or removed if perms.SudoersRule is empty). The
// session is counted and the username recorded in the state file.
func (m *UserManager) EnsureUser(zitiIdentity, username string, perms IdentityPermissions) error {
	if err := ValidateManagedUsername(username); err != nil {
		return fmt.Errorf("identity %q: %w", zitiIdentity, err)
	}

	// Phase 1 (global lock, fast): session bookkeeping and per-user lock.
	m.mu.Lock()
	m.sessions[username]++
	isFirst := m.sessions[username] == 1
	ul, ok := m.userLocks[username]
	if !ok {
		ul = &sync.Mutex{}
		m.userLocks[username] = ul
	}
	m.mu.Unlock()

	// Phase 2 (per-user lock): ownership verification and OS operations.
	ul.Lock()
	defer ul.Unlock()

	if err := m.ensureOwnedAccount(zitiIdentity, username); err != nil {
		m.rollbackSession(username)
		return err
	}

	if err := m.ops.SetGroups(username, perms.Groups); err != nil {
		// Non-fatal: a missing group reduces permissions rather than blocking.
		slog.Error("setting supplementary groups failed", "username", username, "groups", perms.Groups, "err", err)
	}
	if err := m.ops.RemoveLegacySudoers(username); err != nil {
		slog.Error("failed to remove legacy sudoers file", "username", username, "err", err)
	}
	if perms.SudoersRule != "" {
		if err := m.ops.InstallSudoers(username, perms.SudoersRule); err != nil {
			slog.Error("failed to write sudoers file", "username", username, "err", err)
		}
	} else if err := m.ops.RemoveSudoers(username); err != nil {
		slog.Error("failed to remove stale sudoers file", "username", username, "err", err)
	}

	if isFirst {
		if err := m.syncStateFile(); err != nil {
			slog.Error("failed to write state file", "username", username, "err", err)
		}
	}
	return nil
}

// ensureOwnedAccount verifies or establishes ownership of username for
// zitiIdentity. Must be called with the per-user lock held.
func (m *UserManager) ensureOwnedAccount(zitiIdentity, username string) error {
	rec, owned, err := m.registry.Get(username)
	if err != nil {
		return fmt.Errorf("ownership registry: %w", err)
	}
	if owned && rec.Identity != zitiIdentity {
		return fmt.Errorf("username %q (derived from %q) is already in use by Ziti identity %q: connection rejected to prevent privilege collision",
			username, zitiIdentity, rec.Identity)
	}

	uid, exists, err := m.ops.LookupUID(username)
	if err != nil {
		return err
	}

	if exists {
		if !owned {
			return fmt.Errorf("refusing to manage pre-existing account %q (identity %q): it was not created by ziti-ssh-host; if it should be, run \"ziti-ssh-host users claim\"",
				username, zitiIdentity)
		}
		if uid != rec.UID {
			return fmt.Errorf("refusing to manage account %q: uid %d does not match registered uid %d (account was replaced outside ziti-ssh-host)",
				username, uid, rec.UID)
		}
		if uid < MinManagedUID {
			return fmt.Errorf("refusing to manage account %q: uid %d is below %d", username, uid, MinManagedUID)
		}
		return nil
	}

	// Account does not exist. A registry record for it is stale (the account
	// was deleted outside ziti-ssh-host); it is replaced below.
	slog.Info("creating Linux user", "username", username, "ziti_identity", zitiIdentity)
	if err := m.ops.CreateUser(username); err != nil {
		if errors.Is(err, errUserExists) {
			// Created by someone else between lookup and useradd.
			return fmt.Errorf("refusing to manage account %q: it was created concurrently outside ziti-ssh-host", username)
		}
		return err
	}
	uid, exists, err = m.ops.LookupUID(username)
	if err != nil || !exists {
		return fmt.Errorf("account %q not found after useradd (err: %v)", username, err)
	}
	if uid < MinManagedUID {
		// Not registered, so it will never be used or modified. Left for the
		// administrator to remove: deleteUser refuses UIDs below the floor.
		slog.Error("useradd assigned a uid below the managed floor; account not registered and will not be used",
			"username", username, "uid", uid)
		return fmt.Errorf("useradd assigned uid %d below %d to %q; check UID_MIN in /etc/login.defs", uid, MinManagedUID, username)
	}
	if owned {
		if err := m.registry.Remove(username); err != nil {
			return fmt.Errorf("ownership registry: %w", err)
		}
	}
	if err := m.registry.Put(username, OwnerRecord{Identity: zitiIdentity, UID: uid, Created: time.Now().UTC()}); err != nil {
		return fmt.Errorf("ownership registry: %w", err)
	}
	return nil
}

// rollbackSession undoes the session increment from EnsureUser phase 1.
func (m *UserManager) rollbackSession(username string) {
	m.mu.Lock()
	m.sessions[username]--
	if m.sessions[username] <= 0 {
		delete(m.sessions, username)
	}
	m.mu.Unlock()
}

// ReleaseUser decrements the session count for username. When the count
// reaches zero, the sudoers file is removed and — in cleanup mode — the Linux
// user is deleted. Nothing is done to an account that is not in the registry
// with a matching UID.
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
	ul := m.userLocks[username]
	m.mu.Unlock()

	// Phase 2 (per-user lock): slow OS operations.
	if ul != nil {
		ul.Lock()
		defer ul.Unlock()
	}

	// A new session may have started between phase 1 and acquiring the
	// per-user lock; it now owns the account, so do not tear anything down.
	m.mu.Lock()
	reacquired := m.sessions[username] > 0
	m.mu.Unlock()
	if reacquired {
		slog.Info("new session started during release; keeping user", "username", username)
		return nil
	}

	uid, ok := m.verifiedOwnedUID(username)
	if !ok {
		return m.syncStateFile()
	}

	if !m.cleanupOnDisconnect {
		slog.Info("last session closed, cleanup disabled — keeping Linux user", "username", username)
		if err := m.ops.RemoveSudoers(username); err != nil {
			slog.Error("failed to remove sudoers file", "username", username, "err", err)
		}
		if err := m.syncStateFile(); err != nil {
			slog.Error("failed to update state file", "username", username, "err", err)
		}
		return nil
	}

	slog.Info("last session closed, deleting Linux user", "username", username)
	if err := m.ops.DeleteUser(username, uid); err != nil {
		return err
	}
	if err := m.registry.Remove(username); err != nil {
		slog.Error("failed to remove ownership record after deletion", "username", username, "err", err)
	}
	if err := m.syncStateFile(); err != nil {
		slog.Error("failed to update state file after deletion", "username", username, "err", err)
	}
	return nil
}

// verifiedOwnedUID returns the account's UID if it is in the registry, still
// exists with the registered UID, and is at or above MinManagedUID. Any other
// state is logged and reported as not owned. A registry record whose account
// no longer exists is removed.
func (m *UserManager) verifiedOwnedUID(username string) (int, bool) {
	rec, owned, err := m.registry.Get(username)
	if err != nil {
		slog.Error("ownership registry unreadable; not touching account", "username", username, "err", err)
		return 0, false
	}
	if !owned {
		slog.Warn("account not in ownership registry; not touching it", "username", username)
		return 0, false
	}
	uid, exists, err := m.ops.LookupUID(username)
	if err != nil {
		slog.Error("account lookup failed; not touching it", "username", username, "err", err)
		return 0, false
	}
	if !exists {
		slog.Info("registered account no longer exists; removing ownership record", "username", username)
		if err := m.registry.Remove(username); err != nil {
			slog.Error("failed to remove stale ownership record", "username", username, "err", err)
		}
		return 0, false
	}
	if uid != rec.UID || uid < MinManagedUID {
		slog.Warn("account uid does not match ownership record or is below floor; not touching it",
			"username", username, "uid", uid, "registered_uid", rec.UID)
		return 0, false
	}
	return uid, true
}

// CleanupOrphans reads the state file and, in cleanup mode, deletes each
// listed account that is still owned per the registry. It is intended to be
// called at startup, before accepting any connections, to remove users that
// were not cleaned up after a crash. Unowned accounts are dropped from the
// state file without being touched.
//
// Errors deleting individual users are logged but do not stop cleanup of the
// remaining users.
func (m *UserManager) CleanupOrphans() error {
	data, err := os.ReadFile(m.stateFile)
	if os.IsNotExist(err) {
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
			// Accounts are intentionally persistent. Remove any sudoers file
			// left by a crash, but keep the account.
			slog.Info("cleanup disabled; keeping account after restart", "username", username)
			if _, ok := m.verifiedOwnedUID(username); ok {
				if err := m.ops.RemoveSudoers(username); err != nil {
					slog.Error("failed to remove orphan sudoers file", "username", username, "err", err)
				}
			}
			continue
		}
		uid, ok := m.verifiedOwnedUID(username)
		if !ok {
			continue
		}
		slog.Info("cleaning up orphan user", "username", username)
		if err := m.ops.DeleteUser(username, uid); err != nil {
			slog.Error("failed to delete orphan user", "username", username, "err", err)
			remaining = append(remaining, username)
			continue
		}
		if err := m.registry.Remove(username); err != nil {
			slog.Error("failed to remove ownership record after orphan deletion", "username", username, "err", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan state file: %w", err)
	}
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

// SudoersPath returns the sudoers file ziti-ssh-host manages for username:
// /etc/sudoers.d/ziti-ssh-host-<username>. The prefix keeps it from colliding
// with administrator-created files. Usernames are limited to [a-z0-9_-], so
// the name never contains '.' or ends in '~' (which sudo's #includedir skips).
func SudoersPath(username string) string {
	return "/etc/sudoers.d/ziti-ssh-host-" + username
}

// legacySudoersPath is the pre-rename location, /etc/sudoers.d/<username>.
func legacySudoersPath(username string) string {
	return "/etc/sudoers.d/" + username
}

// createSudoers writes a validated sudoers file to SudoersPath(username).
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
	dest := SudoersPath(username)
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("install sudoers file to %q: %w", dest, err)
	}

	slog.Info("created sudoers file", "username", username, "path", dest)
	return nil
}

// removeSudoers removes SudoersPath(username) if it exists.
// A missing file is not treated as an error.
func removeSudoers(username string) error {
	path := SudoersPath(username)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove sudoers file %q: %w", path, err)
	}
	return nil
}

// syncStateFile atomically rewrites the state file from the current contents
// of m.sessions. It briefly acquires m.mu to take a consistent snapshot, then
// releases it before performing file I/O — so callers must not hold m.mu.
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
func (m *UserManager) writeStateFile(lines []string) error {
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return writeFileAtomic(m.stateFile, []byte(content), 0600)
}
