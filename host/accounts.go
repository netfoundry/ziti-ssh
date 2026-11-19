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

package host

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netfoundry/ziti-ssh/ca"
)

// MinManagedUID is the lowest UID ziti-ssh-host will ever create, modify, or
// delete. Accounts below it (root and system accounts) are never touched.
const MinManagedUID = 1000

// ValidateManagedUsername rejects usernames ziti-ssh-host must never manage:
// empty names, names starting with '-' (would be parsed as command options),
// names containing characters outside [a-z0-9_-], and reserved system names.
func ValidateManagedUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username is empty")
	}
	if strings.HasPrefix(username, "-") {
		return fmt.Errorf("username %q must not start with '-'", username)
	}
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("username %q contains invalid character %q", username, r)
		}
	}
	if ca.IsReservedUsername(username) {
		return fmt.Errorf("username %q is reserved and will not be managed", username)
	}
	return nil
}

// errUserExists is returned by accountOps.CreateUser when useradd reports
// that the account already exists (exit code 9).
var errUserExists = errors.New("user already exists")

// accountOps is the set of OS operations UserManager performs. The production
// implementation (osAccountOps) shells out to the standard tools; tests
// substitute a fake so ownership logic can be verified without root.
type accountOps interface {
	// LookupUID returns the account's UID via NSS (getent), and whether it exists.
	LookupUID(username string) (uid int, exists bool, err error)
	// CreateUser creates the account with a home directory. Returns
	// errUserExists if it already exists.
	CreateUser(username string) error
	// SetGroups replaces the account's supplementary groups.
	SetGroups(username string, groups []string) error
	// InstallSudoers writes the validated sudoers file for username.
	InstallSudoers(username, rule string) error
	// RemoveSudoers removes the sudoers file for username, if present.
	RemoveSudoers(username string) error
	// RemoveLegacySudoers removes a pre-rename /etc/sudoers.d/<username> file,
	// but only if its content is in the format ziti-ssh-host wrote.
	RemoveLegacySudoers(username string) error
	// TerminateProcesses ends every process owned by the account (disabling
	// lingering first) but keeps the account. uid must be the verified UID.
	TerminateProcesses(username string, uid int) error
	// DeleteUser terminates the account's processes and removes it with its
	// home directory. uid must be the verified UID of the account.
	DeleteUser(username string, uid int) error
}

// osAccountOps is the production accountOps implementation.
type osAccountOps struct{}

func (osAccountOps) LookupUID(username string) (int, bool, error) {
	cmd := exec.Command("getent", "passwd", "--", username)
	cmd.Env = childEnv()
	out, err := cmd.Output()
	if err != nil {
		// getent exits 2 when the key is not found.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("getent passwd %q: %w", username, err)
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	fields := strings.Split(line, ":")
	if len(fields) < 3 || fields[0] != username {
		return 0, false, fmt.Errorf("getent passwd %q: unexpected output %q", username, line)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, false, fmt.Errorf("getent passwd %q: invalid uid %q", username, fields[2])
	}
	return uid, true, nil
}

func (osAccountOps) CreateUser(username string) error {
	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", "--", username)
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 9 {
			return errUserExists
		}
		return fmt.Errorf("useradd %q: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (osAccountOps) SetGroups(username string, groups []string) error {
	cmd := exec.Command("usermod", "-G", strings.Join(groups, ","), "--", username)
	cmd.Env = childEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -G %q: %w (output: %s)", username, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (osAccountOps) InstallSudoers(username, rule string) error { return createSudoers(username, rule) }
func (osAccountOps) RemoveSudoers(username string) error        { return removeSudoers(username) }

func (osAccountOps) RemoveLegacySudoers(username string) error {
	return removeLegacySudoersFile(legacySudoersPath(username), username)
}

// removeLegacySudoersFile removes path only if it contains exactly the single
// "<username> <rule>" line that ziti-ssh-host used to write there.
func removeLegacySudoersFile(path, username string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read legacy sudoers file %q: %w", path, err)
	}
	// ziti-ssh-host wrote exactly one line: "<username> <rule>\n". Anything
	// else was written by someone else and is left alone.
	content := string(data)
	if !strings.HasPrefix(content, username+" ") || strings.Count(content, "\n") > 1 {
		slog.Warn("leaving legacy sudoers file in place: content not written by ziti-ssh-host", "path", path)
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove legacy sudoers file %q: %w", path, err)
	}
	slog.Info("removed legacy sudoers file", "path", path)
	return nil
}

func (osAccountOps) TerminateProcesses(username string, uid int) error {
	return terminateUserProcesses(username, uid)
}

func (osAccountOps) DeleteUser(username string, uid int) error {
	return deleteUser(username, uid)
}

// userProcessesGone polls pgrep until no processes owned by uid remain or the
// timeout elapses. Returns true when the user has no remaining processes.
func userProcessesGone(uid int, timeout time.Duration) bool {
	const pollInterval = 200 * time.Millisecond
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pgrep := exec.Command("pgrep", "-u", strconv.Itoa(uid))
		pgrep.Env = childEnv()
		err := pgrep.Run()
		if err != nil {
			// pgrep exits 1 when no processes match — user is clear.
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				return true
			}
			slog.Warn("pgrep error while waiting for user processes to exit", "uid", uid, "err", err)
			return false
		}
		time.Sleep(pollInterval)
	}
	return false
}

// terminateUserProcesses ends every process owned by uid: it disables
// lingering (so systemd user services are not restarted), asks loginctl to
// terminate the user's sessions, waits up to 5 s, then escalates to SIGTERM
// (10 s) and SIGKILL (5 s). Processes are matched by the verified UID, never
// by name. The UID floor is re-checked as a last guard.
func terminateUserProcesses(username string, uid int) error {
	if uid < MinManagedUID {
		return fmt.Errorf("refusing to terminate processes of %q: uid %d is below %d", username, uid, MinManagedUID)
	}

	linger := exec.Command("loginctl", "disable-linger", "--", username)
	linger.Env = childEnv()
	if out, err := linger.CombinedOutput(); err != nil {
		slog.Info("loginctl disable-linger returned non-zero (ignored)",
			"username", username, "err", err, "output", strings.TrimSpace(string(out)))
	}

	loginctl := exec.Command("loginctl", "terminate-user", "--", username)
	loginctl.Env = childEnv()
	if out, err := loginctl.CombinedOutput(); err != nil {
		slog.Info("loginctl terminate-user returned non-zero (ignored)",
			"username", username, "err", err, "output", strings.TrimSpace(string(out)))
	}

	uidStr := strconv.Itoa(uid)
	if userProcessesGone(uid, 5*time.Second) {
		return nil
	}
	slog.Info("user processes still running after loginctl; sending SIGTERM", "username", username, "uid", uid)
	pkillTerm := exec.Command("pkill", "-TERM", "-u", uidStr)
	pkillTerm.Env = childEnv()
	if out, err := pkillTerm.CombinedOutput(); err != nil {
		slog.Info("pkill -TERM returned non-zero (ignored)",
			"username", username, "err", err, "output", strings.TrimSpace(string(out)))
	}
	if userProcessesGone(uid, 10*time.Second) {
		return nil
	}
	slog.Warn("user processes still running after SIGTERM; sending SIGKILL", "username", username, "uid", uid)
	pkillKill := exec.Command("pkill", "-KILL", "-u", uidStr)
	pkillKill.Env = childEnv()
	if out, err := pkillKill.CombinedOutput(); err != nil {
		slog.Info("pkill -KILL returned non-zero (ignored)",
			"username", username, "err", err, "output", strings.TrimSpace(string(out)))
	}
	if !userProcessesGone(uid, 5*time.Second) {
		return fmt.Errorf("processes of %q (uid %d) still running after SIGKILL", username, uid)
	}
	return nil
}

// deleteUser removes the sudoers file, terminates the user's processes (see
// terminateUserProcesses), then removes the user and home directory with
// userdel -r. Callers must have verified ownership and that
// uid >= MinManagedUID; the floor is re-checked as a last guard.
func deleteUser(username string, uid int) error {
	if uid < MinManagedUID {
		return fmt.Errorf("refusing to delete %q: uid %d is below %d", username, uid, MinManagedUID)
	}
	if err := removeSudoers(username); err != nil {
		slog.Error("failed to remove sudoers file during deleteUser", "username", username, "err", err)
	}
	if err := terminateUserProcesses(username, uid); err != nil {
		slog.Warn("proceeding with userdel", "username", username, "err", err)
	}

	cmd := exec.Command("userdel", "-r", "--", username)
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 8 {
			return fmt.Errorf("userdel %q: user still has running processes; account not deleted (exit 8): %s",
				username, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("userdel -r %q: %w (output: %s)", username, err, out)
	}
	slog.Info("deleted Linux user", "username", username)
	return nil
}

// legacySudoersDir is where releases before the ownership registry wrote
// sudoers files, named after the bare username.
const legacySudoersDir = "/etc/sudoers.d"

// findLegacySudoersFiles returns the usernames of files in dir that have the
// exact shape older ziti-ssh-host releases wrote: a regular file named after a
// valid, non-reserved username containing a single "<username> <rule>" line.
// Administrators often write files of the same shape, so a match is only a
// candidate, not proof of ownership.
func findLegacySudoersFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %q: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(name, "ziti-ssh-host-") || ValidateManagedUsername(name) != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		content := string(data)
		if strings.HasPrefix(content, name+" ") && strings.Count(content, "\n") <= 1 {
			out = append(out, name)
		}
	}
	return out, nil
}

// LegacySudoersCandidates lists usernames with a legacy-format file in
// /etc/sudoers.d (see findLegacySudoersFiles).
func LegacySudoersCandidates() ([]string, error) {
	return findLegacySudoersFiles(legacySudoersDir)
}

// ReconcileLegacySudoers handles sudoers files left by releases before the
// ownership registry. For accounts in the registry with a verified UID the
// legacy file is removed (it is known to be ziti-ssh-host's). For any other
// candidate a warning is logged and the file is left in place: it may belong
// to an administrator, but if it was written by an old ziti-ssh-host it still
// grants sudo to an account that is no longer managed. Run at startup.
func (m *UserManager) ReconcileLegacySudoers() {
	m.reconcileLegacySudoersIn(legacySudoersDir)
}

func (m *UserManager) reconcileLegacySudoersIn(dir string) {
	names, err := findLegacySudoersFiles(dir)
	if err != nil {
		slog.Error("scanning for legacy sudoers files failed", "err", err)
		return
	}
	for _, u := range names {
		if _, registered, _ := m.registry.Get(u); registered {
			if _, owned := m.verifiedOwnedUID(u); !owned {
				continue // verifiedOwnedUID logged why
			}
			if err := m.ops.RemoveLegacySudoers(u); err != nil {
				slog.Error("failed to remove legacy sudoers file", "username", u, "err", err)
			}
			continue
		}
		slog.Warn("legacy-format sudoers file for an account ziti-ssh-host does not manage; review it: "+
			"if an earlier ziti-ssh-host release wrote it, remove it or run \"ziti-ssh-host users claim\"",
			"path", filepath.Join(dir, u))
	}
}
