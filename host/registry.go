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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// OwnedUsersFileName is the name of the ownership registry file, stored in the
// same directory as the managed-users state file.
const OwnedUsersFileName = "owned-users.json"

// OwnerRecord records that ziti-ssh-host created a Linux account for a Ziti
// identity. The registry is the sole authority for modifying or deleting an
// account: accounts without a matching record are never touched.
type OwnerRecord struct {
	Identity string    `json:"identity"`
	UID      int       `json:"uid"`
	Created  time.Time `json:"created"`
	// Claimed is true when the record was added by "ziti-ssh-host users claim"
	// rather than by ziti-ssh-host creating the account.
	Claimed bool `json:"claimed,omitempty"`
}

// OwnerRegistry is a persistent username → OwnerRecord map stored as JSON.
//
// Every operation re-reads the file under an exclusive flock on a sibling lock
// file and writes it back atomically, so the running daemon and the
// "ziti-ssh-host users" admin commands can safely operate concurrently.
//
// Unlike the managed-users state file, the registry is never cleared on
// startup; a record is removed only after its account has been deleted.
type OwnerRegistry struct {
	path string
}

// NewOwnerRegistry returns a registry backed by path. The file is created on
// first write. A missing file is an empty registry; an unreadable or corrupt
// file is an error on every operation (fail closed).
func NewOwnerRegistry(path string) *OwnerRegistry {
	return &OwnerRegistry{path: path}
}

// Path returns the registry file path.
func (r *OwnerRegistry) Path() string { return r.path }

// Get returns the record for username, if any.
func (r *OwnerRegistry) Get(username string) (OwnerRecord, bool, error) {
	var rec OwnerRecord
	var found bool
	err := r.withLock(func(entries map[string]OwnerRecord) (bool, error) {
		rec, found = entries[username]
		return false, nil
	})
	return rec, found, err
}

// List returns all records keyed by username, sorted by username.
func (r *OwnerRegistry) List() ([]string, map[string]OwnerRecord, error) {
	var out map[string]OwnerRecord
	err := r.withLock(func(entries map[string]OwnerRecord) (bool, error) {
		out = entries
		return false, nil
	})
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, out, err
}

// Put records ownership of username. If a record already exists for a
// different identity, Put returns an error and leaves it unchanged.
func (r *OwnerRegistry) Put(username string, rec OwnerRecord) error {
	return r.withLock(func(entries map[string]OwnerRecord) (bool, error) {
		if existing, ok := entries[username]; ok && existing.Identity != rec.Identity {
			return false, fmt.Errorf("username %q is already registered to Ziti identity %q", username, existing.Identity)
		}
		entries[username] = rec
		return true, nil
	})
}

// Remove deletes the record for username. Removing an absent record is not an
// error.
func (r *OwnerRegistry) Remove(username string) error {
	return r.withLock(func(entries map[string]OwnerRecord) (bool, error) {
		if _, ok := entries[username]; !ok {
			return false, nil
		}
		delete(entries, username)
		return true, nil
	})
}

// withLock loads the registry under an exclusive flock, calls fn, and writes
// the registry back if fn reports a modification.
func (r *OwnerRegistry) withLock(fn func(entries map[string]OwnerRecord) (bool, error)) error {
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}
	lockPath := r.path + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open registry lock %q: %w", lockPath, err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock registry %q: %w", lockPath, err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()

	entries := make(map[string]OwnerRecord)
	data, err := os.ReadFile(r.path)
	switch {
	case os.IsNotExist(err):
		// Empty registry.
	case err != nil:
		return fmt.Errorf("read registry %q: %w", r.path, err)
	case len(data) > 0:
		if err := json.Unmarshal(data, &entries); err != nil {
			return fmt.Errorf("parse registry %q: %w (refusing to manage accounts until the file is repaired)", r.path, err)
		}
	}

	modified, err := fn(entries)
	if err != nil || !modified {
		return err
	}

	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry: %w", err)
	}
	return writeFileAtomic(r.path, append(out, '\n'), 0600)
}

// writeFileAtomic replaces path with data. It writes to a temp file in the same
// directory, fsyncs, renames, then fsyncs the parent directory — so a crash at
// any point leaves either the old or the new file fully intact.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create dir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	fail := func(step string, err error) error {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("%s %q: %w", step, path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail("chmod", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp for %q: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename into %q: %w", path, err)
	}
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		dirF.Close()
	}
	return nil
}
