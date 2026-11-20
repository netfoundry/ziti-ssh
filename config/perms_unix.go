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
	"bufio"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func fileOwner(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// groupFile is the group database read by privateGroup (a variable for tests).
var groupFile = "/etc/group"

// privateGroup reports whether fi's group is its owner's private group (the
// "user private group" scheme used by Debian/Ubuntu, where the default umask
// is 002): the owner's primary group, named after the owner, with no members
// other than the owner. A group-writable file in such a group is writable
// only by its owner, so OpenSSH accepts it too.
func privateGroup(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	owner, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil || owner.Gid != strconv.FormatUint(uint64(st.Gid), 10) {
		return false
	}
	members, found := groupMembers(owner.Gid)
	if !found {
		return false
	}
	grp, err := user.LookupGroupId(owner.Gid)
	if err != nil || grp.Name != owner.Username {
		return false
	}
	for _, m := range members {
		if m != owner.Username {
			return false
		}
	}
	return true
}

// groupMembers returns the explicit member list of gid from groupFile.
// found is false if the group is not listed there (e.g. a directory-service
// group), in which case its members cannot be checked.
func groupMembers(gid string) (members []string, found bool) {
	f, err := os.Open(groupFile)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) != 4 || fields[2] != gid {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		return members, true
	}
	return nil, false
}
