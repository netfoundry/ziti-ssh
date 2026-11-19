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
	"os"
	"path/filepath"
	"testing"
)

func TestCheckUserFile(t *testing.T) {
	dir := t.TempDir()
	if err := CheckUserFile(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing file: %v", err)
	}
	f := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o600, 0o644, 0o640, 0o400} {
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckUserFile(f); err != nil {
			t.Errorf("mode %04o refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o664, 0o666, 0o602, 0o620} {
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckUserFile(f); err == nil {
			t.Errorf("mode %04o accepted", mode)
		}
	}
}
