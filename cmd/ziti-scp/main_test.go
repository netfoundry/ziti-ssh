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

import "testing"

func TestParseArg(t *testing.T) {
	cases := []struct {
		arg              string
		remote           bool
		user, host, path string
		local            string
	}{
		{arg: "web1:/tmp/x", remote: true, host: "web1", path: "/tmp/x"},
		{arg: "bob@web1:/tmp/x", remote: true, user: "bob", host: "web1", path: "/tmp/x"},
		// Identity names may contain '@': split at the last one.
		{arg: "alice@corp.com@web1:f", remote: true, user: "alice@corp.com", host: "web1", path: "f"},
		// A '/' before the first ':' makes it a local path (scp semantics).
		{arg: "/data/a:b", local: "/data/a:b"},
		{arg: "./a:b", local: "./a:b"},
		{arg: "../a:b", local: "../a:b"},
		{arg: "dir/a:b", local: "dir/a:b"},
		{arg: "plain", local: "plain"},
		{arg: `C:\file`, local: `C:\file`},
	}
	for _, c := range cases {
		isRemote, r, local := parseArg(c.arg)
		if isRemote != c.remote {
			t.Errorf("%q: remote=%v, want %v", c.arg, isRemote, c.remote)
			continue
		}
		if !c.remote {
			if local != c.local {
				t.Errorf("%q: local=%q, want %q", c.arg, local, c.local)
			}
			continue
		}
		if r.host != c.host || r.path != c.path || (c.user != "" && r.user != c.user) {
			t.Errorf("%q: got user=%q host=%q path=%q, want %q %q %q", c.arg, r.user, r.host, r.path, c.user, c.host, c.path)
		}
	}
}
