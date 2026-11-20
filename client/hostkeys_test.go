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

package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return newKey(t).PublicKey()
}

func store(t *testing.T) KnownHosts {
	return KnownHosts{Path: filepath.Join(t.TempDir(), "ziti-ssh", "known_hosts")}
}

func TestKnownHostsAddress(t *testing.T) {
	if got := KnownHostsAddress("ssh", "web-server-prod"); got != "web-server-prod@ssh" {
		t.Errorf("terminator dial: %q", got)
	}
	if got := KnownHostsAddress("ssh-db-pool", ""); got != "ssh-db-pool" {
		t.Errorf("service dial: %q", got)
	}
}

func TestHostKeyCallback_TrustOnFirstUse(t *testing.T) {
	kh := store(t)
	var out bytes.Buffer
	cb := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "web@ssh", Notify: &out})
	k := hostKey(t)

	if err := cb("web", nil, k); err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	if !strings.Contains(out.String(), "Permanently added host key for web@ssh") {
		t.Errorf("no notice on first use: %q", out.String())
	}
	if err := cb("web", nil, k); err != nil {
		t.Fatalf("known key refused: %v", err)
	}
	fi, err := os.Stat(kh.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts mode %o, want 600", fi.Mode().Perm())
	}
}

func TestHostKeyCallback_TerminatorAddressRefusesChange(t *testing.T) {
	kh := store(t)
	var out bytes.Buffer
	asked := false
	cb := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "web@ssh", Notify: &out,
		Confirm: func(string) bool { asked = true; return true }})
	if err := cb("web", nil, hostKey(t)); err != nil {
		t.Fatal(err)
	}
	impostor := hostKey(t)
	err := cb("web", nil, impostor)
	if err == nil || !strings.Contains(err.Error(), "has changed") {
		t.Fatalf("changed key accepted: %v", err)
	}
	if asked {
		t.Error("user was asked to accept a changed key for a single-host address")
	}
	if !strings.Contains(out.String(), "ziti-ssh known-hosts remove web@ssh") {
		t.Errorf("warning lacks remediation: %q", out.String())
	}
	if keys, _ := kh.Keys("web@ssh"); len(keys) != 1 {
		t.Errorf("changed key was saved: %d keys", len(keys))
	}
}

func TestHostKeyCallback_ServiceAddressAsksForAdditionalKey(t *testing.T) {
	first, second := hostKey(t), hostKey(t)

	t.Run("accepted", func(t *testing.T) {
		kh := store(t)
		cb := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "pool", MultiHost: true,
			Confirm: func(string) bool { return true }})
		if err := cb("pool", nil, first); err != nil {
			t.Fatal(err)
		}
		if err := cb("pool", nil, second); err != nil {
			t.Fatalf("accepted additional key refused: %v", err)
		}
		if keys, _ := kh.Keys("pool"); len(keys) != 2 {
			t.Fatalf("want both keys remembered, got %d", len(keys))
		}
		// Both members now connect without asking.
		silent := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "pool", MultiHost: true})
		for _, k := range []ssh.PublicKey{first, second} {
			if err := silent("pool", nil, k); err != nil {
				t.Errorf("remembered pool member refused: %v", err)
			}
		}
	})

	t.Run("declined", func(t *testing.T) {
		kh := store(t)
		cb := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "pool", MultiHost: true,
			Confirm: func(string) bool { return false }})
		_ = cb("pool", nil, first)
		if err := cb("pool", nil, second); err == nil {
			t.Fatal("declined key accepted")
		}
		if keys, _ := kh.Keys("pool"); len(keys) != 1 {
			t.Errorf("declined key saved")
		}
	})

	t.Run("non-interactive", func(t *testing.T) {
		kh := store(t)
		cb := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "pool", MultiHost: true})
		_ = cb("pool", nil, first)
		if err := cb("pool", nil, second); err == nil || !strings.Contains(err.Error(), "interactively") {
			t.Fatalf("new key accepted without a terminal: %v", err)
		}
	})
}

func TestKnownHosts_ListAndRemove(t *testing.T) {
	kh := store(t)
	a, b := hostKey(t), hostKey(t)
	for _, e := range []struct {
		addr string
		k    ssh.PublicKey
	}{{"web@ssh", a}, {"pool", a}, {"pool", b}} {
		if err := kh.Add(e.addr, e.k); err != nil {
			t.Fatal(err)
		}
	}
	if err := kh.Add("pool", b); err != nil { // duplicate: no-op
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := kh.List(&out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 3 {
		t.Errorf("list has %d lines, want 3:\n%s", lines, out.String())
	}
	n, err := kh.Remove("pool")
	if err != nil || n != 2 {
		t.Fatalf("remove pool: n=%d err=%v", n, err)
	}
	if keys, _ := kh.Keys("web@ssh"); len(keys) != 1 {
		t.Error("unrelated entry removed")
	}
}

func TestKnownHosts_MalformedFileFailsClosed(t *testing.T) {
	kh := store(t)
	if err := os.MkdirAll(filepath.Dir(kh.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh.Path, []byte("web@ssh not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb := HostKeyCallback(HostKeyPolicy{Store: kh, Address: "web@ssh"})
	if err := cb("web", nil, hostKey(t)); err == nil {
		t.Fatal("connection allowed with an unreadable known_hosts file")
	}
}
