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
// Package packaging holds the nfpm package definitions and their install
// scripts; this test runs the scripts against stub system commands.
package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubs writes fake system commands that log their arguments to log.
func stubs(t *testing.T, log string) string {
	t.Helper()
	dir := t.TempDir()
	logger := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> " + log + "\n"
	for name, body := range map[string]string{
		"systemctl": logger + "exit 0\n",
		"groupadd":  logger + "exit 0\n",
		"pgrep":     "#!/bin/sh\nexit 1\n", // no controller process
		"chown":     logger + "exit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The postinstall scripts restart a running service on upgrade only:
// deb "configure <old-version>" or rpm "$1 >= 2".
func TestPostinstallRestartsOnUpgradeOnly(t *testing.T) {
	cases := []struct {
		args    []string
		restart bool
	}{
		{[]string{"configure", ""}, false},       // deb fresh install
		{[]string{"configure"}, false},           // deb, no old version
		{[]string{"configure", "0.3.0-1"}, true}, // deb upgrade
		{[]string{"abort-upgrade", "0.3.1-1"}, false},
		{[]string{"1"}, false}, // rpm fresh install
		{[]string{"2"}, true},  // rpm upgrade
		{[]string{"12"}, true}, // rpm, several versions installed
	}
	for _, pkg := range []struct{ script, unit, confEnv string }{
		{"scripts/postinstall-ziti-ssh-host.sh", "ziti-ssh-host.service", "ZITI_SSH_HOST_CONF_DIR"},
		{"scripts/postinstall-ziti-ssh-ca.sh", "ziti-ssh-ca.service", "ZITI_SSH_CA_CONF_DIR"},
	} {
		for _, c := range cases {
			name := filepath.Base(pkg.script) + " " + strings.Join(c.args, " ")
			t.Run(name, func(t *testing.T) {
				tmp := t.TempDir()
				log := filepath.Join(tmp, "calls.log")
				conf := filepath.Join(tmp, "conf")
				systemd := filepath.Join(tmp, "systemd")
				for _, d := range []string{conf, systemd} {
					if err := os.MkdirAll(d, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.Command("sh", append([]string{pkg.script}, c.args...)...)
				cmd.Env = []string{
					"PATH=" + stubs(t, log) + ":/usr/bin:/bin",
					pkg.confEnv + "=" + conf,
					"ZITI_SSH_CA_DROPIN_DIR=" + filepath.Join(tmp, "dropin"),
					"ZITI_SSH_SYSTEMD_DIR=" + systemd,
				}
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("script failed: %v\n%s", err, out)
				}
				calls, _ := os.ReadFile(log)
				if !strings.Contains(string(calls), "systemctl daemon-reload") {
					t.Errorf("no daemon-reload; calls:\n%s", calls)
				}
				restarted := strings.Contains(string(calls), "systemctl try-restart "+pkg.unit)
				if restarted != c.restart {
					t.Errorf("try-restart called = %v, want %v; calls:\n%s", restarted, c.restart, calls)
				}
				if _, err := os.Stat(filepath.Join(conf, "env")); err != nil {
					t.Errorf("env file not created: %v", err)
				}
			})
		}
	}
}

// Without systemd (containers, chroots) nothing is reloaded or restarted.
func TestPostinstallWithoutSystemd(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "calls.log")
	cmd := exec.Command("sh", "scripts/postinstall-ziti-ssh-host.sh", "2")
	cmd.Env = []string{
		"PATH=" + stubs(t, log) + ":/usr/bin:/bin",
		"ZITI_SSH_HOST_CONF_DIR=" + tmp,
		"ZITI_SSH_SYSTEMD_DIR=" + filepath.Join(tmp, "absent"),
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	if calls, _ := os.ReadFile(log); strings.Contains(string(calls), "systemctl") {
		t.Errorf("systemctl called without systemd:\n%s", calls)
	}
}
