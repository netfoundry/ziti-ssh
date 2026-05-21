package host_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// ---- Glob pattern resolution tests ------------------------------------------

func TestResolve_CatchAll_MatchesWhenNoOtherEntry(t *testing.T) {
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*": {
				Groups:      []string{"users"},
				SudoersRule: "",
			},
		},
	}

	got := pc.Resolve("stranger@example.com", nil, "")

	if len(got.Groups) != 1 || got.Groups[0] != "users" {
		t.Errorf("Groups = %v, want [users]", got.Groups)
	}
}

func TestResolve_DomainGlob_MatchesIdentityInDomain(t *testing.T) {
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*@corp.com": {
				Groups:      []string{"corp"},
				SudoersRule: "ALL=(ALL) NOPASSWD: /usr/bin/corp-tool",
			},
		},
	}

	got := pc.Resolve("alice@corp.com", nil, "")

	if len(got.Groups) != 1 || got.Groups[0] != "corp" {
		t.Errorf("Groups = %v, want [corp]", got.Groups)
	}
	if got.SudoersRule != "ALL=(ALL) NOPASSWD: /usr/bin/corp-tool" {
		t.Errorf("SudoersRule = %q, want corp-tool rule", got.SudoersRule)
	}
}

func TestResolve_DomainGlob_NoMatchForOtherDomain(t *testing.T) {
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*@corp.com": {Groups: []string{"corp"}},
		},
	}
	globalGroups := []string{"guests"}

	got := pc.Resolve("alice@other.com", globalGroups, "")

	if len(got.Groups) != 1 || got.Groups[0] != "guests" {
		t.Errorf("Groups = %v, want [guests] (global fallback)", got.Groups)
	}
}

func TestResolve_ExactBeatsDomainGlob(t *testing.T) {
	// Exact key "alice@corp.com" must beat the "*@corp.com" glob.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"alice@corp.com": {Groups: []string{"admins"}, SudoersRule: "ALL=(ALL) NOPASSWD: ALL"},
			"*@corp.com":     {Groups: []string{"corp"}},
		},
	}

	got := pc.Resolve("alice@corp.com", nil, "")

	if len(got.Groups) != 1 || got.Groups[0] != "admins" {
		t.Errorf("Groups = %v, want [admins] (exact match)", got.Groups)
	}
	if got.SudoersRule != "ALL=(ALL) NOPASSWD: ALL" {
		t.Errorf("SudoersRule = %q, want ALL rule", got.SudoersRule)
	}
}

func TestResolve_MoreSpecificGlobWins(t *testing.T) {
	// "alice@*" has a 6-char literal prefix ("alice@"); "*@corp.com" has 0.
	// Both match "alice@corp.com" — "alice@*" must win.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"alice@*":    {Groups: []string{"alice-specific"}},
			"*@corp.com": {Groups: []string{"corp-generic"}},
		},
	}

	got := pc.Resolve("alice@corp.com", nil, "")

	if len(got.Groups) != 1 || got.Groups[0] != "alice-specific" {
		t.Errorf("Groups = %v, want [alice-specific] (longer literal prefix wins)", got.Groups)
	}
}

func TestResolve_CatchAllLosesToSpecificGlob(t *testing.T) {
	// "*" has prefix length 0; "*@corp.com" also has prefix length 0 but
	// matches only corp.com identities. When both are present, the domain
	// glob wins for a corp.com identity because it has a longer literal
	// prefix (0 for "*", also 0 for "*@corp.com" but the glob is more
	// specific). Actually "*@corp.com" has prefix 0 and "*" has prefix 0 —
	// equal specificity. This test verifies that the catch-all does NOT
	// override the domain glob when the domain glob is also present and
	// matches, and that the result is one of the two matching entries.
	//
	// Specifically we test that an identity NOT in corp.com still gets the
	// catch-all, and that a corp.com identity gets the corp entry (or at
	// least does not get global fallbacks when a matching glob exists).
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"ops-*": {Groups: []string{"ops"}},
			"*":     {Groups: []string{"default"}},
		},
	}

	// "ops-alice" matches "ops-*" (prefix 4) and "*" (prefix 0) — ops-* wins.
	got := pc.Resolve("ops-alice", nil, "global-fallback-should-not-appear")
	if len(got.Groups) != 1 || got.Groups[0] != "ops" {
		t.Errorf("Groups = %v, want [ops] (ops-* more specific than *)", got.Groups)
	}

	// "dev-bob" matches only "*" — should get default.
	got = pc.Resolve("dev-bob", nil, "global-fallback-should-not-appear")
	if len(got.Groups) != 1 || got.Groups[0] != "default" {
		t.Errorf("Groups = %v, want [default] (catch-all)", got.Groups)
	}
}

func TestResolve_GlobNoMatch_FallsThruToEnvVars(t *testing.T) {
	// A glob that doesn't match the identity should not prevent the env var
	// fallback from being returned.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*@other.com": {Groups: []string{"other"}},
		},
	}
	globalGroups := []string{"everyone"}
	globalSudoers := "ALL=(ALL) NOPASSWD: /usr/bin/less"

	got := pc.Resolve("alice@corp.com", globalGroups, globalSudoers)

	if len(got.Groups) != 1 || got.Groups[0] != "everyone" {
		t.Errorf("Groups = %v, want [everyone] (env var fallback)", got.Groups)
	}
	if got.SudoersRule != globalSudoers {
		t.Errorf("SudoersRule = %q, want %q", got.SudoersRule, globalSudoers)
	}
}

func TestResolve_SuffixGlobBeatesCatchAll(t *testing.T) {
	// "*@dba" (prefixLen=0, totalLiterals=4) must beat "*" (prefixLen=0, totalLiterals=0)
	// for an identity that matches both.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*": {
				Groups:      []string{"adm"},
				SudoersRule: "",
			},
			"*@dba": {
				Groups:      []string{"adm"},
				SudoersRule: "ALL=(ALL) NOPASSWD: /bin/systemctl *",
			},
		},
	}

	got := pc.Resolve("edwardm@dba", nil, "")

	if got.SudoersRule != "ALL=(ALL) NOPASSWD: /bin/systemctl *" {
		t.Errorf("SudoersRule = %q, want systemctl rule (*@dba should beat *)", got.SudoersRule)
	}
}

func TestResolve_DomainGlobBeatesCatchAll_TotalLiterals(t *testing.T) {
	// "*@corp.com" (prefixLen=0, totalLiterals=9) must beat "*" (prefixLen=0, totalLiterals=0)
	// for a corp.com identity.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*": {
				Groups:      []string{"everyone"},
				SudoersRule: "",
			},
			"*@corp.com": {
				Groups:      []string{"corp"},
				SudoersRule: "ALL=(ALL) NOPASSWD: /usr/bin/corp-tool",
			},
		},
	}

	got := pc.Resolve("alice@corp.com", nil, "")

	if len(got.Groups) != 1 || got.Groups[0] != "corp" {
		t.Errorf("Groups = %v, want [corp] (*@corp.com should beat *)", got.Groups)
	}
	if got.SudoersRule != "ALL=(ALL) NOPASSWD: /usr/bin/corp-tool" {
		t.Errorf("SudoersRule = %q, want corp-tool rule", got.SudoersRule)
	}
}

func TestResolve_GlobGlobalsNotMerged(t *testing.T) {
	// A glob-matched entry that has an empty SudoersRule must NOT inherit
	// the global sudoers rule.
	pc := &host.PermissionsConfig{
		Permissions: map[string]host.IdentityPermissions{
			"*@corp.com": {
				Groups: []string{"corp"},
				// SudoersRule deliberately empty
			},
		},
	}
	globalSudoers := "ALL=(ALL) NOPASSWD: ALL"

	got := pc.Resolve("alice@corp.com", nil, globalSudoers)

	if got.SudoersRule != "" {
		t.Errorf("SudoersRule = %q, want empty (global must not be merged into glob match)", got.SudoersRule)
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

	const identity = "test-identity-01"
	if err := mgr.EnsureUser(identity, username, perms); err != nil {
		t.Fatalf("EnsureUser returned error: %v", err)
	}

	// Second call (same identity, second concurrent session) must not error.
	if err := mgr.EnsureUser(identity, username, perms); err != nil {
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
	const identity = "test-identity-refcnt"
	for i := 0; i < 3; i++ {
		if err := mgr.EnsureUser(identity, username, perms); err != nil {
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

func TestEnsureUser_CollisionRejected(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("EnsureUser collision test requires root (useradd); skipping")
	}

	dir := t.TempDir()
	mgr := host.NewUserManager(filepath.Join(dir, "state"), true)

	// "alice.corp" and "alice_corp" are different Ziti identities that both
	// derive to the Linux username "alice_corp" (period → underscore).
	const (
		identityA = "alice.corp"
		identityB = "alice_corp"
		username  = "alice_corp"
	)
	t.Cleanup(func() { exec.Command("userdel", "-r", username).Run() })

	if err := mgr.EnsureUser(identityA, username, host.IdentityPermissions{}); err != nil {
		t.Fatalf("EnsureUser(identityA): %v", err)
	}

	// identityB collides with identityA's Linux account — must be rejected.
	err := mgr.EnsureUser(identityB, username, host.IdentityPermissions{})
	if err == nil {
		t.Fatal("expected collision error for identityB, got nil")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("expected 'already in use' in error, got: %v", err)
	}
}
