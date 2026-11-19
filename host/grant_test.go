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
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, sudoers, groups, restrict string) GrantPolicy {
	t.Helper()
	p, err := ParseGrantPolicy(sudoers, groups, restrict)
	if err != nil {
		t.Fatalf("ParseGrantPolicy(%q, %q, %q): %v", sudoers, groups, restrict, err)
	}
	return p
}

func TestParseGrantPolicy_Invalid(t *testing.T) {
	cases := []struct{ sudoers, groups, restrict string }{
		{"ssh ops", "", ""},       // whitespace in service name
		{"ssh:ops", "", ""},       // ':' in service name
		{"", "sudo", ""},          // group without service
		{"", "ssh-ops:", ""},      // empty group
		{"", ":sudo", ""},         // empty service
		{"", "ssh-ops:su do", ""}, // whitespace in group
		{"", "ssh-*:sudo", ""},    // wildcard inside a service name
		{"", "", "yes"},           // not true/false
	}
	for _, c := range cases {
		if _, err := ParseGrantPolicy(c.sudoers, c.groups, c.restrict); err == nil {
			t.Errorf("ParseGrantPolicy(%q, %q, %q) accepted invalid input", c.sudoers, c.groups, c.restrict)
		}
	}
}

func TestGrantPolicy_DefaultPolicy(t *testing.T) {
	p := mustPolicy(t, "", "", "")

	if err := p.Check("ssh", IdentityPermissions{Groups: []string{"developers", "mysql"}}); err != nil {
		t.Errorf("ordinary groups refused by default: %v", err)
	}
	if err := p.Check("ssh", IdentityPermissions{}); err != nil {
		t.Errorf("empty permissions refused: %v", err)
	}
	for _, g := range PrivilegedGroups {
		if err := p.Check("ssh", IdentityPermissions{Groups: []string{"developers", g}}); err == nil {
			t.Errorf("privileged group %q allowed by default", g)
		}
	}
	err := p.Check("ssh", IdentityPermissions{SudoersRule: "ALL=(ALL) NOPASSWD: ALL"})
	if err == nil || !strings.Contains(err.Error(), "ZITI_ALLOW_SUDOERS") {
		t.Errorf("sudoers_rule allowed by default: %v", err)
	}
}

func TestGrantPolicy_PerServiceOptIn(t *testing.T) {
	// The role-tier example: ssh-ops may grant root, ssh-db may not.
	p := mustPolicy(t, "ssh-ops", "ssh-ops:sudo, ssh-ops:docker", "")

	root := IdentityPermissions{Groups: []string{"sudo", "docker"}, SudoersRule: "ALL=(ALL) NOPASSWD: ALL"}
	if err := p.Check("ssh-ops", root); err != nil {
		t.Errorf("opted-in service refused: %v", err)
	}
	if err := p.Check("ssh-db", IdentityPermissions{SudoersRule: "ALL=(ALL) ALL"}); err == nil {
		t.Error("sudoers_rule allowed from a service that was not opted in")
	}
	if err := p.Check("ssh-db", IdentityPermissions{Groups: []string{"sudo"}}); err == nil {
		t.Error("privileged group allowed from a service that was not opted in")
	}
	if err := p.Check("ssh-db", IdentityPermissions{Groups: []string{"mysql"}}); err != nil {
		t.Errorf("ordinary group refused on other service: %v", err)
	}
}

func TestGrantPolicy_Wildcards(t *testing.T) {
	p := mustPolicy(t, "*", "*:docker", "")
	if err := p.Check("anything", IdentityPermissions{Groups: []string{"docker"}, SudoersRule: "ALL=(ALL) ALL"}); err != nil {
		t.Errorf("wildcard opt-in not applied: %v", err)
	}
	if err := p.Check("anything", IdentityPermissions{Groups: []string{"sudo"}}); err == nil {
		t.Error("*:docker must not allow other privileged groups")
	}
}

func TestGrantPolicy_RestrictGroups(t *testing.T) {
	p := mustPolicy(t, "", "*:developers,ssh-ops:ops", "true")
	if err := p.Check("ssh-ops", IdentityPermissions{Groups: []string{"developers", "ops"}}); err != nil {
		t.Errorf("listed groups refused in strict mode: %v", err)
	}
	// A custom group that may carry sudo rights in the host's own sudoers.
	if err := p.Check("ssh-db", IdentityPermissions{Groups: []string{"ops"}}); err == nil {
		t.Error("group listed for another service allowed in strict mode")
	}
	if err := p.Check("ssh-ops", IdentityPermissions{Groups: []string{"mysql"}}); err == nil {
		t.Error("unlisted ordinary group allowed in strict mode")
	}
}

func TestGrantPolicy_Describe(t *testing.T) {
	p := mustPolicy(t, "ssh-ops", "ssh-ops:sudo", "")
	if d := p.Describe("ssh-ops"); !strings.Contains(d, "sudoers_rule allowed") || !strings.Contains(d, "explicitly allowed: sudo") {
		t.Errorf("Describe(ssh-ops) = %q", d)
	}
	if d := p.Describe("ssh-db"); !strings.Contains(d, "sudoers_rule refused") || strings.Contains(d, "explicitly allowed") {
		t.Errorf("Describe(ssh-db) = %q", d)
	}
}

func TestResolveWithSource(t *testing.T) {
	pc := &PermissionsConfig{Permissions: map[string]IdentityPermissions{
		"alice": {Groups: []string{"a"}},
		"dba-*": {Groups: []string{"b"}},
		"*":     {Groups: []string{"c"}},
	}}
	for _, id := range []string{"alice", "dba-carol", "someone-else"} {
		if _, fromConfig := pc.ResolveWithSource(id, []string{"fallback"}, "ALL=(ALL) ALL"); !fromConfig {
			t.Errorf("%q: config match reported as fallback", id)
		}
	}

	// Without a catch-all, unmatched identities use the host's fallbacks,
	// which are not subject to the grant policy.
	noCatchAll := &PermissionsConfig{Permissions: map[string]IdentityPermissions{"alice": {}}}
	perms, fromConfig := noCatchAll.ResolveWithSource("bob", []string{"sudo"}, "ALL=(ALL) ALL")
	if fromConfig || perms.SudoersRule == "" {
		t.Errorf("fallback reported as config (fromConfig=%v, perms=%+v)", fromConfig, perms)
	}
	var nilConfig *PermissionsConfig
	if _, fromConfig := nilConfig.ResolveWithSource("bob", nil, ""); fromConfig {
		t.Error("no config attached reported as config")
	}
}

func TestGrantPolicy_EnforceSkipsHostFallbacks(t *testing.T) {
	p := mustPolicy(t, "", "", "")
	root := IdentityPermissions{Groups: []string{"sudo"}, SudoersRule: "ALL=(ALL) NOPASSWD: ALL"}
	if err := p.Enforce("ssh", root, false); err != nil {
		t.Errorf("host-owned fallback refused: %v", err)
	}
	if err := p.Enforce("ssh", root, true); err == nil {
		t.Error("the same grant from a config entry was not refused")
	}
}
