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

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "alice", true},
		{"*", "", true},
		{"*", "team/alice", true}, // path.Match: '*' stopped at '/'
		{"dba-*", "dba-carol", true},
		{"dba-*", "ops-carol", false},
		{"*@corp.com", "alice@corp.com", true},
		{"*@corp.com", "alice@corp.com.evil", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"[ab]*", "a-team", false}, // path.Match: character class
		{"[ab]*", "[ab]-team", true},
		{`dev\*`, `dev\anything`, true}, // path.Match: escaped '*'
		{"é*", "éclair", true},
	}
	for _, c := range cases {
		if got := MatchPattern(c.pattern, c.name); got != c.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestResolve_EqualSpecificityIsDeterministic(t *testing.T) {
	// "*a*" and "*b*" both match "ab" with equal specificity (0, 1); the
	// lexically smaller pattern must win every time, regardless of map order.
	pc := &PermissionsConfig{Permissions: map[string]IdentityPermissions{
		"*-ops": {Groups: []string{"ops"}},
		"*-dba": {Groups: []string{"dba"}},
		"*-x":   {Groups: []string{"x"}},
		"x-*":   {Groups: []string{"prefix"}},
	}}
	pc2 := &PermissionsConfig{Permissions: map[string]IdentityPermissions{
		"*b*": {Groups: []string{"b"}},
		"*a*": {Groups: []string{"a"}},
	}}
	for i := 0; i < 200; i++ {
		if got := pc2.Resolve("ab", nil, ""); len(got.Groups) != 1 || got.Groups[0] != "a" {
			t.Fatalf("iteration %d: got %v, want [a]", i, got.Groups)
		}
		if got := pc.Resolve("x-ops", nil, ""); got.Groups[0] != "prefix" {
			t.Fatalf("prefix should win: %v", got.Groups)
		}
	}
}

func TestPatternWarnings(t *testing.T) {
	pc := &PermissionsConfig{Permissions: map[string]IdentityPermissions{
		"[ab]*": {}, `dev\*`: {}, "dba-*": {}, "alice": {},
	}}
	w := pc.PatternWarnings()
	if len(w) != 2 || !strings.Contains(w[0]+w[1], "[ab]*") || !strings.Contains(w[0]+w[1], `dev\\*`) {
		t.Errorf("warnings: %v", w)
	}
}
