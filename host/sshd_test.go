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

import "testing"

func TestPlanSSHDReload(t *testing.T) {
	cases := []struct {
		name string
		st   sshdState
		want sshdReloadPlan
	}{
		{
			// Ubuntu 24.04 after any SSH login: ssh.socket (Accept=no) has
			// started a long-running ssh.service. Previously skipped entirely,
			// so the running sshd never loaded TrustedUserCAKeys.
			name: "socket Accept=no with running service",
			st:   sshdState{ServiceActive: true, SocketActive: true, SocketPerConn: false},
			want: sshdReloadPlan{ReloadService: true, HUPOrphans: true},
		},
		{
			name: "socket Accept=no, service not yet started",
			st:   sshdState{ServiceActive: false, SocketActive: true, SocketPerConn: false},
			want: sshdReloadPlan{ReloadService: false, HUPOrphans: true},
		},
		{
			name: "traditional ssh.service only",
			st:   sshdState{ServiceActive: true, SocketActive: false},
			want: sshdReloadPlan{ReloadService: true, HUPOrphans: true},
		},
		{
			// Every connection's sshd has PPID 1: never signal them.
			name: "socket Accept=yes (per-connection sshd)",
			st:   sshdState{ServiceActive: false, SocketActive: true, SocketPerConn: true},
			want: sshdReloadPlan{ReloadService: false, HUPOrphans: false},
		},
		{
			name: "sshd not managed by systemd units",
			st:   sshdState{},
			want: sshdReloadPlan{ReloadService: false, HUPOrphans: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := planSSHDReload(tc.st); got != tc.want {
				t.Errorf("planSSHDReload(%+v) = %+v, want %+v", tc.st, got, tc.want)
			}
		})
	}
}
