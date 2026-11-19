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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOps is an in-memory accountOps that records every mutating call.
type fakeOps struct {
	mu        sync.Mutex
	users     map[string]int // username → uid
	nextUID   int
	createErr error
	fail      map[string]error // op ("groups", "sudoers", "rmsudoers", "rmlegacy") → error to return
	calls     []string
}

func (f *fakeOps) failure(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[op]
}

func newFakeOps() *fakeOps {
	return &fakeOps{users: map[string]int{}, nextUID: 1001, fail: map[string]error{}}
}

func (f *fakeOps) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeOps) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeOps) LookupUID(u string) (int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	uid, ok := f.users[u]
	return uid, ok, nil
}

func (f *fakeOps) CreateUser(u string) error {
	f.record("create:" + u)
	if f.createErr != nil {
		return f.createErr
	}
	f.mu.Lock()
	f.users[u] = f.nextUID
	f.nextUID++
	f.mu.Unlock()
	return nil
}

func (f *fakeOps) SetGroups(u string, g []string) error {
	f.record("groups:" + u + ":" + strings.Join(g, ","))
	return f.failure("groups")
}
func (f *fakeOps) InstallSudoers(u, r string) error {
	f.record("sudoers:" + u)
	return f.failure("sudoers")
}
func (f *fakeOps) RemoveSudoers(u string) error {
	f.record("rmsudoers:" + u)
	return f.failure("rmsudoers")
}
func (f *fakeOps) RemoveLegacySudoers(u string) error {
	f.record("rmlegacy:" + u)
	return f.failure("rmlegacy")
}
func (f *fakeOps) TerminateProcesses(u string, uid int) error {
	f.record("terminate:" + u)
	return nil
}
func (f *fakeOps) DeleteUser(u string, uid int) error {
	f.record("delete:" + u)
	f.mu.Lock()
	delete(f.users, u)
	f.mu.Unlock()
	return nil
}

func testManager(t *testing.T, dir string, ops *fakeOps, cleanup bool) *UserManager {
	t.Helper()
	reg := NewOwnerRegistry(filepath.Join(dir, OwnedUsersFileName))
	return newUserManager(filepath.Join(dir, "managed-users"), reg, ops, cleanup)
}

var adminPerms = IdentityPermissions{Groups: []string{"sudo"}, SudoersRule: "ALL=(ALL) NOPASSWD: ALL"}

// ---- pre-existing accounts ----------------------------------------------------

func TestEnsureUser_PreExistingAccountNotAdopted(t *testing.T) {
	ops := newFakeOps()
	ops.users["alice"] = 1000 // e.g. an administrator's own account
	m := testManager(t, t.TempDir(), ops, true)

	err := m.EnsureUser("alice", "alice", adminPerms)
	if err == nil || !strings.Contains(err.Error(), "pre-existing account") {
		t.Fatalf("expected pre-existing account rejection, got %v", err)
	}
	for _, c := range []string{"create:", "groups:", "sudoers:", "rmsudoers:", "rmlegacy:", "delete:"} {
		if ops.called(c) {
			t.Errorf("unexpected OS call %q on a pre-existing account", c)
		}
	}
	if n := m.sessions["alice"]; n != 0 {
		t.Errorf("session count = %d after rejection, want 0", n)
	}
}

func TestEnsureUser_ReservedAndInvalidNamesRejected(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, true)
	for _, u := range []string{"root", "ubuntu", "sshd", "-ou0", "", "a.b"} {
		if err := m.EnsureUser("x", u, IdentityPermissions{}); err == nil {
			t.Errorf("EnsureUser(%q) succeeded, want rejection", u)
		}
	}
	if len(ops.calls) != 0 {
		t.Errorf("OS calls made for rejected names: %v", ops.calls)
	}
}

func TestEnsureUser_CreatesAndRegisters(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, false)

	if err := m.EnsureUser("alice@corp", "alice_corp", adminPerms); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	rec, ok, err := m.registry.Get("alice_corp")
	if err != nil || !ok {
		t.Fatalf("registry record missing: ok=%v err=%v", ok, err)
	}
	if rec.Identity != "alice@corp" || rec.UID != 1001 || rec.Claimed {
		t.Errorf("unexpected record %+v", rec)
	}
	if !ops.called("groups:alice_corp:sudo") || !ops.called("sudoers:alice_corp") {
		t.Errorf("permissions not applied: %v", ops.calls)
	}
}

func TestEnsureUser_OwnershipSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, false)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseUser("alice"); err != nil {
		t.Fatal(err)
	}

	// Restart: new manager, same registry file.
	m2 := testManager(t, dir, ops, false)
	ops.calls = nil
	if err := m2.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatalf("owner reconnect after restart rejected: %v", err)
	}
	if ops.called("create:") {
		t.Error("account recreated instead of reused")
	}
}

func TestEnsureUser_CollisionRejectedAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, false)
	// "alice.corp" and "alice_corp" both derive "alice_corp".
	if err := m.EnsureUser("alice.corp", "alice_corp", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseUser("alice_corp"); err != nil {
		t.Fatal(err)
	}

	m2 := testManager(t, dir, ops, false)
	err := m2.EnsureUser("alice_corp", "alice_corp", adminPerms)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected collision rejection after restart, got %v", err)
	}
}

func TestEnsureUser_ReplacedAccountRejected(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, true)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	// Account deleted and recreated outside ziti-ssh-host with a new UID.
	ops.users["alice"] = 1500

	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err == nil ||
		!strings.Contains(err.Error(), "does not match registered uid") {
		t.Fatalf("expected UID mismatch rejection, got %v", err)
	}
	// Releasing the original session must not delete the replacement account.
	ops.calls = nil
	if err := m.ReleaseUser("alice"); err != nil {
		t.Fatal(err)
	}
	if ops.called("delete:") || ops.called("rmsudoers:") {
		t.Errorf("replacement account was modified on release: %v", ops.calls)
	}
}

func TestEnsureUser_LowUIDNeverManaged(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, true)
	// Even a registry record cannot authorize a low-UID account.
	ops.users["svc"] = 999
	if err := m.registry.Put("svc", OwnerRecord{Identity: "svc", UID: 999}); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureUser("svc", "svc", adminPerms); err == nil {
		t.Fatal("low-UID account was managed")
	}

	// useradd assigning a low UID is rejected and the account is not registered.
	ops.nextUID = 500
	if err := m.EnsureUser("bob", "bob", adminPerms); err == nil {
		t.Fatal("account with low assigned UID accepted")
	}
	if _, ok, _ := m.registry.Get("bob"); ok {
		t.Error("low-UID account was registered")
	}
	if ops.called("groups:") || ops.called("sudoers:") {
		t.Errorf("permissions applied to low-UID account: %v", ops.calls)
	}
}

func TestEnsureUser_ConcurrentOutsideCreationRejected(t *testing.T) {
	ops := newFakeOps()
	ops.createErr = errUserExists
	m := testManager(t, t.TempDir(), ops, true)
	if err := m.EnsureUser("alice", "alice", adminPerms); err == nil {
		t.Fatal("useradd exit 9 treated as success")
	}
	if _, ok, _ := m.registry.Get("alice"); ok {
		t.Error("account registered after useradd reported it already existed")
	}
	if ops.called("groups:") || ops.called("sudoers:") {
		t.Errorf("permissions applied: %v", ops.calls)
	}
}

func TestEnsureUser_RemovesLegacySudoersForOwnedAccount(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, true)
	if err := m.EnsureUser("alice", "alice", adminPerms); err != nil {
		t.Fatal(err)
	}
	if !ops.called("rmlegacy:alice") {
		t.Error("legacy sudoers file not migrated for owned account")
	}
}

// ---- release / cleanup --------------------------------------------------------

func TestReleaseUser_DeletesOnlyOwnedAccount(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, true)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseUser("alice"); err != nil {
		t.Fatal(err)
	}
	if !ops.called("delete:alice") {
		t.Error("owned account not deleted in cleanup mode")
	}
	if _, ok, _ := m.registry.Get("alice"); ok {
		t.Error("registry record kept after deletion")
	}

	// A session whose registry record disappears must not lead to deletion.
	if err := m.EnsureUser("bob", "bob", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	if err := m.registry.Remove("bob"); err != nil {
		t.Fatal(err)
	}
	ops.calls = nil
	if err := m.ReleaseUser("bob"); err != nil {
		t.Fatal(err)
	}
	if ops.called("delete:") {
		t.Error("unregistered account deleted")
	}
}

func TestReleaseUser_NewSessionDuringReleaseKeepsAccount(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, true)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}

	ops.mu.Lock()
	ops.calls = nil
	ops.mu.Unlock()

	// Hold the per-user lock so ReleaseUser blocks after phase 1.
	ul := m.userLocks["alice"]
	ul.Lock()
	done := make(chan error, 1)
	go func() { done <- m.ReleaseUser("alice") }()

	// Wait for phase 1 to drop the session count to zero.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		_, present := m.sessions["alice"]
		m.mu.Unlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ReleaseUser phase 1 did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A new session arrives (EnsureUser phase 1) before release takes the lock.
	m.mu.Lock()
	m.sessions["alice"]++
	m.mu.Unlock()
	ul.Unlock()

	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if ops.called("delete:") || ops.called("rmsudoers:") {
		t.Errorf("account torn down under a live session: %v", ops.calls)
	}
}

func TestReleaseUser_RejectedCollisionDoesNotBlockTeardown(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, true)
	// "alice.corp" owns alice_corp; "alice_corp" derives the same username.
	if err := m.EnsureUser("alice.corp", "alice_corp", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	ops.mu.Lock()
	ops.calls = nil
	ops.mu.Unlock()

	ul := m.userLocks["alice_corp"]
	ul.Lock()

	// The colliding identity connects while the owner's last session ends.
	collider := make(chan error, 1)
	go func() { collider <- m.EnsureUser("alice_corp", "alice_corp", IdentityPermissions{}) }()
	time.Sleep(50 * time.Millisecond) // let it reach the per-user lock

	release := make(chan error, 1)
	go func() { release <- m.ReleaseUser("alice_corp") }()

	// The owner's release must see zero sessions: the rejected attempt must
	// not have been counted.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		_, present := m.sessions["alice_corp"]
		m.mu.Unlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			ul.Unlock()
			<-collider
			<-release
			t.Fatal("owner's release saw an open session counted for a not-yet-verified connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ul.Unlock()

	// Either order is correct once the lock is released: if the collider runs
	// first it is rejected (owned by alice.corp); if the release runs first the
	// owner's account and record are deleted, and the collider then gets a
	// fresh account of its own. In both cases the owner's teardown happens.
	collErr := <-collider
	if err := <-release; err != nil {
		t.Fatal(err)
	}
	if !ops.called("delete:alice_corp") {
		t.Errorf("owner's account was not torn down: %v", ops.calls)
	}
	if collErr == nil {
		rec, ok, _ := m.registry.Get("alice_corp")
		if !ok || rec.Identity != "alice_corp" {
			t.Errorf("collider accepted without a fresh account of its own: %+v", rec)
		}
	} else if !strings.Contains(collErr.Error(), "already in use") {
		t.Errorf("unexpected collider error: %v", collErr)
	}
}

func TestCleanupOrphans_SkipsUnownedAccounts(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, true)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	// State file also lists an account ziti-ssh-host never created.
	ops.users["carol"] = 1000
	if err := os.WriteFile(m.stateFile, []byte("alice\ncarol\n"), 0600); err != nil {
		t.Fatal(err)
	}

	m2 := testManager(t, dir, ops, true)
	ops.calls = nil
	if err := m2.CleanupOrphans(); err != nil {
		t.Fatal(err)
	}
	if !ops.called("delete:alice") {
		t.Error("owned orphan not deleted")
	}
	if ops.called("delete:carol") {
		t.Error("unowned account deleted by orphan cleanup")
	}
	data, _ := os.ReadFile(m.stateFile)
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("state file not cleared: %q", data)
	}
}

// ---- claim / registry ---------------------------------------------------------

func TestClaimAccount(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	ops.users["alice"] = 1002
	ops.users["svc"] = 999
	reg := NewOwnerRegistry(filepath.Join(dir, OwnedUsersFileName))

	if _, err := claimAccount(reg, ops, "svc", "svc"); err == nil {
		t.Error("low-UID account claimed")
	}
	if _, err := claimAccount(reg, ops, "nobody-here", "nobody-here"); err == nil {
		t.Error("missing account claimed")
	}
	if _, err := claimAccount(reg, ops, "root", "root"); err == nil {
		t.Error("reserved account claimed")
	}

	rec, err := claimAccount(reg, ops, "alice", "alice")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !rec.Claimed || rec.UID != 1002 {
		t.Errorf("unexpected record %+v", rec)
	}
	if _, err := claimAccount(reg, ops, "alice", "alice"); err != nil {
		t.Errorf("re-claim by same identity should be a no-op: %v", err)
	}
	if _, err := claimAccount(reg, ops, "alice", "Alice"); err == nil {
		t.Error("claim by a different identity succeeded")
	}

	// The claimed account is now usable by its identity.
	m := newUserManager(filepath.Join(dir, "managed-users"), reg, ops, false)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatalf("EnsureUser after claim: %v", err)
	}
}

func TestOwnerRegistry_CorruptFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, OwnedUsersFileName)
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewUserManager(filepath.Join(dir, "managed-users"), true); err == nil {
		t.Fatal("NewUserManager accepted a corrupt registry")
	}
	ops := newFakeOps()
	m := newUserManager(filepath.Join(dir, "managed-users"), NewOwnerRegistry(path), ops, true)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err == nil {
		t.Fatal("EnsureUser succeeded with a corrupt registry")
	}
	if len(ops.calls) != 0 {
		t.Errorf("OS calls made with corrupt registry: %v", ops.calls)
	}
}

func TestOwnerRegistry_FileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), OwnedUsersFileName)
	reg := NewOwnerRegistry(path)
	if err := reg.Put("alice", OwnerRecord{Identity: "alice", UID: 1001}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("registry mode = %o, want 600", st.Mode().Perm())
	}
}

// ---- legacy sudoers migration -------------------------------------------------

func TestRemoveLegacySudoersFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content string
		wantRemoved   bool
	}{
		{"written by ziti-ssh-host", "alice ALL=(ALL) NOPASSWD: ALL\n", true},
		{"admin file, other user", "bob ALL=(ALL) ALL\n", false},
		{"admin file, multiple lines", "alice ALL=(ALL) ALL\nDefaults:alice !requiretty\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "alice")
			if err := os.WriteFile(p, []byte(tc.content), 0440); err != nil {
				t.Fatal(err)
			}
			if err := removeLegacySudoersFile(p, "alice"); err != nil {
				t.Fatal(err)
			}
			_, err := os.Stat(p)
			removed := os.IsNotExist(err)
			if removed != tc.wantRemoved {
				t.Errorf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			os.Remove(p)
		})
	}
}

func TestSudoersPath_Prefixed(t *testing.T) {
	if got := SudoersPath("admins"); got != "/etc/sudoers.d/ziti-ssh-host-admins" {
		t.Errorf("SudoersPath = %q", got)
	}
}

func TestLegacySudoers_FindAndReconcile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0440); err != nil {
			t.Fatal(err)
		}
	}
	write("alice", "alice ALL=(ALL) NOPASSWD: ALL\n")                   // owned below → removed
	write("bob", "bob ALL=(ALL) ALL\n")                                 // not registered → warn only
	write("carol", "carol ALL=(ALL) ALL\nDefaults:carol !requiretty\n") // multi-line → not a candidate
	write("README", "dave ALL=(ALL) ALL\n")                             // invalid username → ignored
	write("root", "root ALL=(ALL) ALL\n")                               // reserved → ignored
	write("ziti-ssh-host-erin", "erin ALL=(ALL) ALL\n")                 // current format → ignored

	got, err := findLegacySudoersFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("candidates = %v, want [alice bob]", got)
	}

	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, false)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	ops.users["bob"] = 1000 // exists, never registered
	ops.calls = nil

	m.reconcileLegacySudoersIn(dir)
	if !ops.called("rmlegacy:alice") {
		t.Error("legacy file for registered account not removed")
	}
	if ops.called("rmlegacy:bob") {
		t.Error("legacy-format file for unregistered account was removed")
	}
}

// ---- H5: fail closed when permissions cannot be applied --------------------

func TestEnsureUser_PermissionFailuresRejectConnection(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name      string
		failOp    string
		perms     IdentityPermissions
		wantCalls []string // must have been attempted
		notCalls  []string // must not have been attempted
	}{
		{"groups fail", "groups", adminPerms, nil, []string{"sudoers:"}},
		{"legacy sudoers removal fails", "rmlegacy", adminPerms, nil, []string{"sudoers:"}},
		// A failed install must also remove any existing file so an older rule
		// cannot stay in force.
		{"sudoers install fails", "sudoers", adminPerms, []string{"rmsudoers:alice"}, nil},
		{"sudoers removal fails (no rule configured)", "rmsudoers", IdentityPermissions{Groups: []string{"dev"}}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeOps()
			m := testManager(t, t.TempDir(), ops, false)
			ops.fail[tc.failOp] = boom

			err := m.EnsureUser("alice", "alice", tc.perms)
			if err == nil || !errors.Is(err, boom) {
				t.Fatalf("want rejection wrapping the failure, got %v", err)
			}
			if n := m.sessions["alice"]; n != 0 {
				t.Errorf("rejected connection counted as a session (count %d)", n)
			}
			for _, c := range tc.wantCalls {
				if !ops.called(c) {
					t.Errorf("expected call %q; calls: %v", c, ops.calls)
				}
			}
			for _, c := range tc.notCalls {
				if ops.called(c) {
					t.Errorf("unexpected call %q after failure; calls: %v", c, ops.calls)
				}
			}
		})
	}
}

func TestEnsureUser_RecoversAfterConfigFixed(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, false)
	ops.fail["groups"] = errors.New("group 'dokcer' does not exist")
	if err := m.EnsureUser("alice", "alice", adminPerms); err == nil {
		t.Fatal("want rejection while config is broken")
	}
	delete(ops.fail, "groups")
	if err := m.EnsureUser("alice", "alice", adminPerms); err != nil {
		t.Fatalf("connection still rejected after config fixed: %v", err)
	}
	if m.sessions["alice"] != 1 {
		t.Errorf("session count = %d, want 1", m.sessions["alice"])
	}
}

func TestReleaseUser_ClearsGroupsAndSudoersWhenKeepingAccount(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, false) // cleanup off: account kept
	if err := m.EnsureUser("alice", "alice", adminPerms); err != nil {
		t.Fatal(err)
	}
	ops.calls = nil
	if err := m.ReleaseUser("alice"); err != nil {
		t.Fatal(err)
	}
	if !ops.called("groups:alice:") || ops.called("groups:alice:sudo") {
		t.Errorf("supplementary groups not cleared on last release: %v", ops.calls)
	}
	if !ops.called("rmsudoers:alice") {
		t.Errorf("sudoers not removed on last release: %v", ops.calls)
	}
	if ops.called("delete:") {
		t.Errorf("account deleted with cleanup disabled: %v", ops.calls)
	}
}

func TestCleanupOrphans_ClearsGroupsWhenKeepingAccounts(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, false)
	if err := m.EnsureUser("alice", "alice", adminPerms); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash: state file still lists alice; a new manager starts.
	m2 := testManager(t, dir, ops, false)
	ops.calls = nil
	if err := m2.CleanupOrphans(); err != nil {
		t.Fatal(err)
	}
	if !ops.called("groups:alice:") || !ops.called("rmsudoers:alice") {
		t.Errorf("orphan privileges not dropped after restart: %v", ops.calls)
	}
}

// ---- H12: opt-in termination of a kept account's processes ----------------

func TestReleaseUser_TerminateOnDisconnect(t *testing.T) {
	t.Run("on: privileges dropped, then processes ended, account kept", func(t *testing.T) {
		ops := newFakeOps()
		m := testManager(t, t.TempDir(), ops, false)
		m.SetTerminateOnDisconnect(true)
		if err := m.EnsureUser("alice", "alice", adminPerms); err != nil {
			t.Fatal(err)
		}
		ops.calls = nil
		if err := m.ReleaseUser("alice"); err != nil {
			t.Fatal(err)
		}
		idx := func(prefix string) int {
			for i, c := range ops.calls {
				if strings.HasPrefix(c, prefix) {
					return i
				}
			}
			return -1
		}
		term, groups, sudo := idx("terminate:alice"), idx("groups:alice:"), idx("rmsudoers:alice")
		if term < 0 {
			t.Fatalf("processes not terminated: %v", ops.calls)
		}
		if groups < 0 || sudo < 0 || groups > term || sudo > term {
			t.Errorf("privileges must be dropped before termination: %v", ops.calls)
		}
		if ops.called("delete:") {
			t.Errorf("account deleted although cleanup is off: %v", ops.calls)
		}
	})

	t.Run("off (default): processes left running", func(t *testing.T) {
		ops := newFakeOps()
		m := testManager(t, t.TempDir(), ops, false)
		if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
			t.Fatal(err)
		}
		if err := m.ReleaseUser("alice"); err != nil {
			t.Fatal(err)
		}
		if ops.called("terminate:") {
			t.Errorf("processes terminated with the setting off: %v", ops.calls)
		}
	})

	t.Run("not while other sessions remain", func(t *testing.T) {
		ops := newFakeOps()
		m := testManager(t, t.TempDir(), ops, false)
		m.SetTerminateOnDisconnect(true)
		for i := 0; i < 2; i++ {
			if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.ReleaseUser("alice"); err != nil {
			t.Fatal(err)
		}
		if ops.called("terminate:") {
			t.Errorf("processes terminated while a session is still open: %v", ops.calls)
		}
	})

	t.Run("never for unregistered or replaced accounts", func(t *testing.T) {
		ops := newFakeOps()
		m := testManager(t, t.TempDir(), ops, false)
		m.SetTerminateOnDisconnect(true)
		if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
			t.Fatal(err)
		}
		ops.users["alice"] = 1500 // replaced outside ziti-ssh-host
		if err := m.EnsureUser("bob", "bob", IdentityPermissions{}); err != nil {
			t.Fatal(err)
		}
		if err := m.registry.Remove("bob"); err != nil { // no longer registered
			t.Fatal(err)
		}
		ops.calls = nil
		_ = m.ReleaseUser("alice")
		_ = m.ReleaseUser("bob")
		if ops.called("terminate:") {
			t.Errorf("terminated processes of an account not verifiably owned: %v", ops.calls)
		}
	})
}

func TestCleanupOrphans_TerminateOnDisconnect(t *testing.T) {
	dir := t.TempDir()
	ops := newFakeOps()
	m := testManager(t, dir, ops, false)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	// Crash, then restart with the setting on.
	m2 := testManager(t, dir, ops, false)
	m2.SetTerminateOnDisconnect(true)
	ops.calls = nil
	if err := m2.CleanupOrphans(); err != nil {
		t.Fatal(err)
	}
	if !ops.called("terminate:alice") || ops.called("delete:") {
		t.Errorf("want processes of the orphaned account ended and the account kept: %v", ops.calls)
	}
}

// ---- M10: managed accounts are restricted to certificate login --------------

func TestSSHDDropIn_DisablesKeyFilesForManagedGroup(t *testing.T) {
	got := SSHDDropIn("/etc/ssh/ziti_ca.pub")
	for _, want := range []string{
		"TrustedUserCAKeys /etc/ssh/ziti_ca.pub\n",
		"Match Group " + ManagedGroup + "\n",
		"    AuthorizedKeysFile none\n",
		"    AuthorizedKeysCommand none\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("drop-in missing %q:\n%s", want, got)
		}
	}
	// TrustedUserCAKeys must come before the Match block (global scope).
	if strings.Index(got, "TrustedUserCAKeys") > strings.Index(got, "Match Group") {
		t.Error("TrustedUserCAKeys must precede the Match block")
	}
}

func TestEnsureSSHDDropIn_RewritesOnlyWhenDifferent(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "ziti-ssh.conf")
	// A drop-in from an earlier release.
	if err := os.WriteFile(conf, []byte("TrustedUserCAKeys /etc/ssh/ziti_ca.pub\n"), 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := EnsureSSHDDropIn(conf, "/etc/ssh/ziti_ca.pub")
	if err != nil || !changed {
		t.Fatalf("old drop-in not upgraded: changed=%v err=%v", changed, err)
	}
	changed, err = EnsureSSHDDropIn(conf, "/etc/ssh/ziti_ca.pub")
	if err != nil || changed {
		t.Fatalf("up-to-date drop-in rewritten: changed=%v err=%v", changed, err)
	}
}

func TestEnsureUser_AlwaysInManagedGroup(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, false)
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{Groups: []string{"dev", ManagedGroup}}); err != nil {
		t.Fatal(err)
	}
	if !ops.called("groups:alice:dev," + ManagedGroup) {
		t.Errorf("managed group not added exactly once: %v", ops.calls)
	}
	ops.calls = nil
	if err := m.EnsureUser("alice", "alice", IdentityPermissions{}); err != nil {
		t.Fatal(err)
	}
	if !ops.called("groups:alice:" + ManagedGroup) {
		t.Errorf("account with no configured groups not kept in managed group: %v", ops.calls)
	}
	ops.calls = nil
	_ = m.ReleaseUser("alice")
	_ = m.ReleaseUser("alice")
	if !ops.called("groups:alice:"+ManagedGroup) || ops.called("groups:alice:dev") {
		t.Errorf("release must drop configured groups but keep the managed group: %v", ops.calls)
	}
}
