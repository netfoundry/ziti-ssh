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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "ziti-ssh <target>" runs connect and must accept connect's flags.
func TestRootAcceptsConnectFlags(t *testing.T) {
	root := newRootCmd()
	if err := root.ParseFlags([]string{"-N", "-L", "8080:db:5432", "-D", "1080", "-R", "9000:localhost:3000", "--service", "ssh-ops", "host"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n, _ := root.Flags().GetBool("no-shell"); !n {
		t.Error("-N not set")
	}
	// The flags are shared with connect, so connect's RunE sees the values.
	for name, want := range map[string]string{"local-forward": "8080:db:5432", "dynamic": "1080", "remote-forward": "9000:localhost:3000", "service": "ssh-ops"} {
		if got := connectCmd.Flags().Lookup(name).Value.String(); !strings.Contains(got, want) {
			t.Errorf("connect --%s = %q, want %q", name, got, want)
		}
	}
}

// Runtime errors print the error only; flag errors still print usage.
func TestUsageOnlyForFlagErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ZITI_IDENTITY", "")
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		root := newRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		err := root.Execute()
		return out.String(), err
	}
	out, err := run("--config", cfg, "somehost")
	if err == nil || !strings.Contains(err.Error(), "--identity") {
		t.Fatalf("want missing-identity error, got %v", err)
	}
	if strings.Contains(out, "Usage:") {
		t.Errorf("runtime error printed usage:\n%s", out)
	}
	out, err = run("--no-such-flag", "somehost")
	if err == nil || !strings.Contains(out, "Usage:") {
		t.Errorf("flag error: err %v, output lacks usage:\n%s", err, out)
	}
}
