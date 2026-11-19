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

package main

import (
	"io"
	"os"
	"testing"
)

func TestCheckAgentForwarding(t *testing.T) {
	if err := checkAgentForwarding(false, false); err != nil {
		t.Errorf("no -A: %v", err)
	}
	if err := checkAgentForwarding(true, false); err == nil {
		t.Error("-A allowed without --forward-agent-unverified")
	}
	if err := checkAgentForwarding(true, true); err != nil {
		t.Errorf("-A with --forward-agent-unverified refused: %v", err)
	}
}

func TestResolveKey_NonInteractiveNeverPrompts(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no SSH keys

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	_, resolveErr := resolveKey("", false)
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)

	if resolveErr == nil {
		t.Fatal("want an error when no key exists in non-interactive mode")
	}
	if len(out) != 0 {
		t.Fatalf("non-interactive resolveKey wrote to stdout (would corrupt the proxied SSH stream): %q", out)
	}
}

func TestParseTarget_SplitsAtLastAt(t *testing.T) {
	cases := map[string][2]string{
		"bob@web1":            {"bob", "web1"},
		"alice@corp.com@web1": {"alice@corp.com", "web1"},
	}
	for in, want := range cases {
		u, h, err := parseTarget(in)
		if err != nil || u != want[0] || h != want[1] {
			t.Errorf("parseTarget(%q) = %q, %q, %v; want %q, %q", in, u, h, err, want[0], want[1])
		}
	}
	if _, h, err := parseTarget("web1"); err != nil || h != "web1" {
		t.Errorf("parseTarget(web1) = %q, %v", h, err)
	}
}
