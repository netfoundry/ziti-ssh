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

func TestParseForwardSpecs(t *testing.T) {
	l, err := parseLocalForward("[::1]:8080:[2001:db8::1]:80")
	if err != nil || l.Bind != "::1" || l.LocalPort != "8080" || l.RemoteHost != "2001:db8::1" || l.RemotePort != "80" {
		t.Errorf("IPv6 -L: %+v, %v", l, err)
	}
	l, err = parseLocalForward("8080:db:5432")
	if err != nil || l.Bind != "127.0.0.1" || l.RemoteHost != "db" {
		t.Errorf("3-part -L: %+v, %v", l, err)
	}
	r, err := parseRemoteForward("[::]:9000:localhost:3000")
	if err != nil || r.Bind != "::" || r.RemotePort != "9000" || r.LocalHost != "localhost" || r.LocalPort != "3000" {
		t.Errorf("IPv6 -R: %+v, %v", r, err)
	}
	d, err := parseDynamicForward("[::1]:1080")
	if err != nil || d.Bind != "::1" || d.LocalPort != "1080" {
		t.Errorf("IPv6 -D: %+v, %v", d, err)
	}
	for _, bad := range []string{"0:db:80", "8080:db:65536", "x:db:80", "8080::80", "[::1:8080:db:80", "[::1]x:8080:db:80"} {
		if _, err := parseLocalForward(bad); err == nil {
			t.Errorf("-L %q accepted", bad)
		}
	}
	if _, err := parseDynamicForward("99999"); err == nil {
		t.Error("-D 99999 accepted")
	}
}

func TestIsLoopbackBind(t *testing.T) {
	for _, b := range []string{"", "localhost", "127.0.0.1", "127.0.0.2", "::1"} {
		if !isLoopbackBind(b) {
			t.Errorf("%q not loopback", b)
		}
	}
	for _, b := range []string{"0.0.0.0", "::", "*", "192.168.1.5", "example.com"} {
		if isLoopbackBind(b) {
			t.Errorf("%q treated as loopback", b)
		}
	}
}
