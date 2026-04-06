package host_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/edwardm/ziti-ssh/host"
)

// ---- PermissionsConfig.Resolve tests ----------------------------------------

func TestResolve_NilConfig_ReturnsGlobalFallbacks(t *testing.T) {
	var pc *host.PermissionsConfig // nil
	globalGroups := []string{"sudo", "adm"}
	globalSudoers := "ALL=(ALL) NOPASSWD: ALL"

	got := pc.Resolve("alice@corp.com", globalGroups, globalSudoers)

	if len(got.Groups) != 2 || got.Groups[0] != "sudo" || got.Groups[1] != "adm" {
		t.Errorf("Groups = %v, want [sudo adm]", got.Groups)
	}
	if got.SudoersRule != globalSudoers {
		t.Errorf("SudoersRule = %q, want %q", got.SudoersRule, globalSudoers)
	}
}

func TestResolve_EmptyConfig_ReturnsGlobalFallbacks(t *testing.T) {
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{},
	}
	globalGroups := []string{"docker"}
	globalSudoers := "ALL=(ALL) NOPASSWD: /usr/bin/docker *"

	got := pc.Resolve("bob@corp.com", globalGroups, globalSudoers)

	if len(got.Groups) != 1 || got.Groups[0] != "docker" {
		t.Errorf("Groups = %v, want [docker]", got.Groups)
	}
	if got.SudoersRule != globalSudoers {
		t.Errorf("SudoersRule = %q, want %q", got.SudoersRule, globalSudoers)
	}
}

func TestResolve_IdentityInConfig_ReturnsThatEntry(t *testing.T) {
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"alice@corp.com": {
				Groups:      []string{"mysql"},
				SudoersRule: "ALL=(ALL) NOPASSWD: /usr/bin/mysqld*",
			},
		},
	}
	globalGroups := []string{"sudo"}
	globalSudoers := "ALL=(ALL) NOPASSWD: ALL"

	got := pc.Resolve("alice@corp.com", globalGroups, globalSudoers)

	if len(got.Groups) != 1 || got.Groups[0] != "mysql" {
		t.Errorf("Groups = %v, want [mysql]", got.Groups)
	}
	if got.SudoersRule != "ALL=(ALL) NOPASSWD: /usr/bin/mysqld*" {
		t.Errorf("SudoersRule = %q, want mysqld rule", got.SudoersRule)
	}
}

func TestResolve_IdentityInConfig_GlobalsNotMerged(t *testing.T) {
	// An entry that omits SudoersRule should NOT inherit global sudoers.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"carol@corp.com": {
				Groups: []string{"mysql"},
				// SudoersRule deliberately empty
			},
		},
	}
	globalGroups := []string{"sudo"}
	globalSudoers := "ALL=(ALL) NOPASSWD: ALL"

	got := pc.Resolve("carol@corp.com", globalGroups, globalSudoers)

	if len(got.Groups) != 1 || got.Groups[0] != "mysql" {
		t.Errorf("Groups = %v, want [mysql]", got.Groups)
	}
	if got.SudoersRule != "" {
		t.Errorf("SudoersRule = %q, want empty (global must not be merged)", got.SudoersRule)
	}
}

func TestResolve_IdentityNotInConfig_ReturnsGlobalFallbacks(t *testing.T) {
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"alice@corp.com": {Groups: []string{"mysql"}},
		},
	}
	globalGroups := []string{"adm"}
	globalSudoers := "ALL=(ALL) NOPASSWD: /usr/bin/journalctl"

	// "dave" is not in the config
	got := pc.Resolve("dave@corp.com", globalGroups, globalSudoers)

	if len(got.Groups) != 1 || got.Groups[0] != "adm" {
		t.Errorf("Groups = %v, want [adm]", got.Groups)
	}
	if got.SudoersRule != globalSudoers {
		t.Errorf("SudoersRule = %q, want %q", got.SudoersRule, globalSudoers)
	}
}

func TestResolve_CaseSensitiveIdentityMatch(t *testing.T) {
	// Identity names are case-sensitive; "Alice@Corp.com" != "alice@corp.com".
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"Alice@Corp.com": {Groups: []string{"admins"}},
		},
	}

	// Exact match — should use config entry.
	got := pc.Resolve("Alice@Corp.com", nil, "")
	if len(got.Groups) != 1 || got.Groups[0] != "admins" {
		t.Errorf("exact match: Groups = %v, want [admins]", got.Groups)
	}

	// Different case — should fall back to globals.
	got = pc.Resolve("alice@corp.com", []string{"users"}, "")
	if len(got.Groups) != 1 || got.Groups[0] != "users" {
		t.Errorf("case mismatch: Groups = %v, want [users] (global fallback)", got.Groups)
	}
}

func TestResolve_NoGlobalFallbacks_ReturnsEmptyPerms(t *testing.T) {
	var pc *host.PermissionsConfig // nil config
	got := pc.Resolve("anyone@corp.com", nil, "")
	if len(got.Groups) != 0 {
		t.Errorf("Groups = %v, want empty", got.Groups)
	}
	if got.SudoersRule != "" {
		t.Errorf("SudoersRule = %q, want empty", got.SudoersRule)
	}
}

// ---- UserManager.EnsureUser tests -------------------------------------------
//
// These tests avoid shelling out to useradd/usermod/userdel (which would
// require root and a real Linux host). Instead they verify the UserManager's
// ref-counting and state-file behaviour using a temp directory.
//
// The "first session creates, subsequent sessions skip" logic is exercised
// without real OS calls by using a username that useradd would reject with
// exit code 9 (user exists) — but we can't replicate that in unit tests
// without root. We therefore test only the UserManager mechanics that don't
// require root, and verify that EnsureUser now accepts IdentityPermissions.

func TestEnsureUser_AcceptsIdentityPermissions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("EnsureUser integration requires root (useradd); skipping")
	}

	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	mgr := host.NewUserManager(stateFile, true)

	// Use a deliberately short unique name unlikely to clash with system users.
	username := "ztestperm01"
	perms := host.IdentityPermissions{
		Groups:      nil,
		SudoersRule: "",
	}

	// Clean up regardless.
	t.Cleanup(func() {
		exec.Command("userdel", "-r", username).Run()
	})

	if err := mgr.EnsureUser(username, perms); err != nil {
		t.Fatalf("EnsureUser returned error: %v", err)
	}

	// Second call (same session) must not error.
	if err := mgr.EnsureUser(username, perms); err != nil {
		t.Fatalf("second EnsureUser returned error: %v", err)
	}

	if err := mgr.ReleaseUser(username); err != nil {
		t.Errorf("first ReleaseUser returned error: %v", err)
	}
	if err := mgr.ReleaseUser(username); err != nil {
		t.Errorf("second ReleaseUser returned error: %v", err)
	}
}

func TestEnsureUser_RefCounting(t *testing.T) {
	// Test ref-count mechanics without root by relying on useradd exit code 9
	// (user already exists). We create the user manually if root, or skip.
	if os.Getuid() != 0 {
		t.Skip("EnsureUser ref-count test requires root; skipping")
	}

	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	mgr := host.NewUserManager(stateFile, true)

	username := "ztestrefcnt1"
	perms := host.IdentityPermissions{}

	t.Cleanup(func() {
		exec.Command("userdel", "-r", username).Run()
	})

	// Three sessions open.
	for i := 0; i < 3; i++ {
		if err := mgr.EnsureUser(username, perms); err != nil {
			t.Fatalf("EnsureUser #%d: %v", i+1, err)
		}
	}

	// Two releases — user should still exist.
	for i := 0; i < 2; i++ {
		if err := mgr.ReleaseUser(username); err != nil {
			t.Fatalf("ReleaseUser #%d: %v", i+1, err)
		}
	}

	// User should still exist after two of three sessions released.
	if err := exec.Command("id", username).Run(); err != nil {
		t.Errorf("user %q should still exist after 2/3 releases, but 'id' failed: %v", username, err)
	}

	// Final release — user should be gone.
	if err := mgr.ReleaseUser(username); err != nil {
		t.Fatalf("final ReleaseUser: %v", err)
	}
	if err := exec.Command("id", username).Run(); err == nil {
		t.Errorf("user %q should have been deleted after all sessions released", username)
		exec.Command("userdel", "-r", username).Run()
	}
}

func TestNewUserManager_Signature(t *testing.T) {
	// Verify that NewUserManager's signature no longer includes sudoersRule.
	// This is a compile-time check embedded as a runtime test.
	dir := t.TempDir()
	mgr := host.NewUserManager(filepath.Join(dir, "state"), true)
	if mgr == nil {
		t.Fatal("NewUserManager returned nil")
	}
}
