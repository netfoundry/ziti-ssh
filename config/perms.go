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

package config

import (
	"errors"
	"fmt"
	"os"
)

// CheckUserFile refuses a file that another user could have written, as
// OpenSSH does for its per-user client config ("Bad owner or permissions"):
// it must be owned by the current user (or root), not writable by others,
// and not writable by its group unless that group is the owner's private
// group (Debian/Ubuntu default umask 002). A missing file is not an error.
func CheckUserFile(path string) error {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Group write is accepted only for the owner's private group (see
	// privateGroup), as OpenSSH does; world write never.
	if perm := fi.Mode().Perm(); perm&0o002 != 0 || (perm&0o020 != 0 && !privateGroup(fi)) {
		return fmt.Errorf("bad permissions on %s (%04o): it must not be writable by others or by a shared group (chmod go-w %s)",
			path, perm, path)
	}
	if uid, ok := fileOwner(fi); ok && uid != 0 && uid != os.Getuid() {
		return fmt.Errorf("bad owner of %s (uid %d): it must be owned by you or root", path, uid)
	}
	return nil
}
