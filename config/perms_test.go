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

//go:build unix

package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func writeMode(t *testing.T, f string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(f, mode); err != nil {
		t.Fatal(err)
	}
}

func TestCheckUserFile(t *testing.T) {
	dir := t.TempDir()
	if err := CheckUserFile(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing file: %v", err)
	}
	f := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No group file entry: group write is never accepted.
	old := groupFile
	t.Cleanup(func() { groupFile = old })
	groupFile = filepath.Join(dir, "no-such-group-file")

	for _, mode := range []os.FileMode{0o600, 0o644, 0o640, 0o400} {
		writeMode(t, f, mode)
		if err := CheckUserFile(f); err != nil {
			t.Errorf("mode %04o refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o664, 0o666, 0o602, 0o620} {
		writeMode(t, f, mode)
		if err := CheckUserFile(f); err == nil {
			t.Errorf("mode %04o accepted without a private group", mode)
		}
	}
}

// Debian/Ubuntu give each user a private group and a umask of 002, so files
// are created 0664. That must be accepted, as OpenSSH does — but only while
// the group has no other members.
func TestCheckUserFile_UserPrivateGroup(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	grp, err := user.LookupGroupId(me.Gid)
	if err != nil || grp.Name != me.Username {
		t.Skipf("primary group of %q is not a private group (%v)", me.Username, err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(f, []byte("x"), 0o664); err != nil {
		t.Fatal(err)
	}
	writeMode(t, f, 0o664)

	old := groupFile
	t.Cleanup(func() { groupFile = old })
	gf := filepath.Join(dir, "group")

	for _, members := range []string{"", me.Username} {
		if err := os.WriteFile(gf, []byte(fmt.Sprintf("%s:x:%s:%s\n", grp.Name, me.Gid, members)), 0o644); err != nil {
			t.Fatal(err)
		}
		groupFile = gf
		if err := CheckUserFile(f); err != nil {
			t.Errorf("private group (members %q): 0664 refused: %v", members, err)
		}
	}

	if err := os.WriteFile(gf, []byte(fmt.Sprintf("%s:x:%s:%s,mallory\n", grp.Name, me.Gid, me.Username)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckUserFile(f); err == nil {
		t.Error("0664 accepted although the group has another member")
	}

	writeMode(t, f, 0o666)
	if err := CheckUserFile(f); err == nil {
		t.Error("world-writable file accepted")
	}
}
