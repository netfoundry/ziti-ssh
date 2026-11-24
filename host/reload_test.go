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
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestFirstActiveUnit(t *testing.T) {
	active := func(set ...string) func(string) bool {
		return func(u string) bool {
			for _, s := range set {
				if s == u {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name   string
		active []string
		want   string
	}{
		{"ubuntu", []string{"ssh.service", "sshd.service"}, "ssh.service"}, // sshd.service is an alias there
		{"rhel", []string{"sshd.service"}, "sshd.service"},
		{"none", nil, ""},
	}
	for _, c := range cases {
		if got := firstActiveUnit(active(c.active...), sshdServiceUnits...); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if got := firstActiveUnit(active("sshd.socket"), sshdSocketUnits...); got != "sshd.socket" {
		t.Errorf("socket: got %q", got)
	}
}

// Child processes must not inherit NOTIFY_SOCKET: systemd logs a warning for
// every notification from a PID other than the service's main PID.
func TestCommandStripsNotifySocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	cmd := command("true")
	if cmd.Env == nil {
		t.Fatal("command left Env nil (would inherit the full environment)")
	}
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "NOTIFY_SOCKET=") {
			t.Fatalf("NOTIFY_SOCKET passed to child: %q", e)
		}
	}
	if len(cmd.Env) != len(os.Environ())-1 {
		t.Errorf("env has %d entries, want %d", len(cmd.Env), len(os.Environ())-1)
	}
}

func TestLogged(t *testing.T) {
	if Logged(nil) != nil {
		t.Error("Logged(nil) != nil")
	}
	base := fmt.Errorf("wrapped: %w", ErrPermissionConflict)
	err := Logged(base)
	if !IsLogged(err) || !IsLogged(fmt.Errorf("outer: %w", err)) {
		t.Error("IsLogged false for a Logged error")
	}
	if !errors.Is(err, ErrPermissionConflict) {
		t.Error("Logged hides the wrapped error from errors.Is")
	}
	if err.Error() != base.Error() {
		t.Errorf("message changed: %q", err.Error())
	}
	if IsLogged(base) {
		t.Error("IsLogged true for a plain error")
	}
}
