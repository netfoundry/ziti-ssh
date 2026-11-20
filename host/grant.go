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
	"fmt"
	"sort"
	"strings"
)

// PrivilegedGroups are Linux groups that are root-equivalent (or nearly so) on
// common distributions. A ziti-ssh-host.v1 config may grant them only for
// services the host owner has opted in via ZITI_ALLOW_GROUPS.
var PrivilegedGroups = []string{"root", "sudo", "admin", "wheel", "docker", "lxd", "disk", "shadow", "libvirt"}

// GrantPolicy is the host owner's limit on what a ziti-ssh-host.v1 config —
// written by whoever can edit configs on the Ziti controller — may grant on
// this host, per Ziti service. It does not apply to the host's own fallbacks
// (ZITI_SSH_GROUPS, ZITI_SUDOERS_RULE).
//
// The zero value is the default policy: no service may set sudoers_rule, and
// any group except PrivilegedGroups may be granted.
type GrantPolicy struct {
	sudoersAll      bool
	sudoersServices map[string]bool
	groupsAll       map[string]bool            // "*:<group>"
	groupsByService map[string]map[string]bool // "<service>:<group>"
	restrictGroups  bool
}

// ParseGrantPolicy builds a GrantPolicy from the host settings:
//
//	allowSudoers  ZITI_ALLOW_SUDOERS   "svc1,svc2" or "*"; empty = none
//	allowGroups   ZITI_ALLOW_GROUPS    "svc:group,*:group,..."; empty = none
//	restrict      ZITI_RESTRICT_GROUPS "true"/"false"; empty = false
func ParseGrantPolicy(allowSudoers, allowGroups, restrict string) (GrantPolicy, error) {
	p := GrantPolicy{
		sudoersServices: map[string]bool{},
		groupsAll:       map[string]bool{},
		groupsByService: map[string]map[string]bool{},
	}

	for _, svc := range splitList(allowSudoers) {
		if svc == "*" {
			p.sudoersAll = true
			continue
		}
		if err := validateToken(svc); err != nil {
			return GrantPolicy{}, fmt.Errorf("ZITI_ALLOW_SUDOERS: service %q: %w", svc, err)
		}
		p.sudoersServices[svc] = true
	}

	for _, item := range splitList(allowGroups) {
		svc, group, ok := strings.Cut(item, ":")
		if !ok {
			return GrantPolicy{}, fmt.Errorf("ZITI_ALLOW_GROUPS: entry %q must be <service>:<group> (use *:<group> for all services)", item)
		}
		svc, group = strings.TrimSpace(svc), strings.TrimSpace(group)
		if err := validateToken(group); err != nil {
			return GrantPolicy{}, fmt.Errorf("ZITI_ALLOW_GROUPS: entry %q: group: %w", item, err)
		}
		if svc == "*" {
			p.groupsAll[group] = true
			continue
		}
		if err := validateToken(svc); err != nil {
			return GrantPolicy{}, fmt.Errorf("ZITI_ALLOW_GROUPS: entry %q: service: %w", item, err)
		}
		if p.groupsByService[svc] == nil {
			p.groupsByService[svc] = map[string]bool{}
		}
		p.groupsByService[svc][group] = true
	}

	switch strings.ToLower(strings.TrimSpace(restrict)) {
	case "", "false":
	case "true":
		p.restrictGroups = true
	default:
		return GrantPolicy{}, fmt.Errorf("ZITI_RESTRICT_GROUPS: must be true or false, got %q", restrict)
	}
	return p, nil
}

// Check reports whether a config entry resolved for service may be applied.
// It returns an error describing the first refused grant.
func (p GrantPolicy) Check(service string, perms IdentityPermissions) error {
	if perms.SudoersRule != "" && !p.sudoersAllowed(service) {
		return fmt.Errorf("sudoers_rule is not permitted from service %q (host setting ZITI_ALLOW_SUDOERS)", service)
	}
	for _, g := range perms.Groups {
		explicit := p.groupsAll[g] || p.groupsByService[service][g]
		switch {
		case p.restrictGroups && !explicit:
			return fmt.Errorf("group %q is not permitted from service %q (ZITI_RESTRICT_GROUPS=true and not listed in ZITI_ALLOW_GROUPS)", g, service)
		case !explicit && isPrivilegedGroup(g):
			return fmt.Errorf("privileged group %q is not permitted from service %q (host setting ZITI_ALLOW_GROUPS, e.g. %s:%s)", g, service, service, g)
		}
	}
	return nil
}

// Enforce applies Check to permissions that came from a ziti-ssh-host.v1
// config entry (fromConfig, from ResolveWithSource). The host's own fallbacks
// (ZITI_SSH_GROUPS, ZITI_SUDOERS_RULE) are set by the host owner and are never
// refused.
func (p GrantPolicy) Enforce(service string, perms IdentityPermissions, fromConfig bool) error {
	if !fromConfig {
		return nil
	}
	return p.Check(service, perms)
}

// Describe summarises the policy for service, for logs and inspect output.
func (p GrantPolicy) Describe(service string) string {
	sudoers := "refused"
	if p.sudoersAllowed(service) {
		sudoers = "allowed"
	}
	var extra []string
	for g := range p.groupsAll {
		extra = append(extra, g)
	}
	for g := range p.groupsByService[service] {
		if !p.groupsAll[g] {
			extra = append(extra, g)
		}
	}
	sort.Strings(extra)
	groups := "any except " + strings.Join(PrivilegedGroups, ", ")
	if p.restrictGroups {
		groups = "only listed"
	}
	if len(extra) > 0 {
		groups += "; explicitly allowed: " + strings.Join(extra, ", ")
	} else if p.restrictGroups {
		groups += " (none listed)"
	}
	return fmt.Sprintf("sudoers_rule %s; groups: %s", sudoers, groups)
}

func (p GrantPolicy) sudoersAllowed(service string) bool {
	return p.sudoersAll || p.sudoersServices[service]
}

func isPrivilegedGroup(g string) bool {
	for _, pg := range PrivilegedGroups {
		if g == pg {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func validateToken(s string) error {
	if s == "" {
		return fmt.Errorf("is empty")
	}
	if strings.ContainsAny(s, " \t:,*") {
		return fmt.Errorf("%q contains whitespace, ':', ',' or '*'", s)
	}
	return nil
}
