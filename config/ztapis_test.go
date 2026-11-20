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
	"strings"
	"testing"
)

func TestPersistZtAPIs_RefusesEmptyList(t *testing.T) {
	f := filepath.Join(t.TempDir(), "identity.json")
	orig := `{"ztAPI":"https://ctrl:443","ztAPIs":["https://ctrl:443"]}`
	if err := os.WriteFile(f, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PersistZtAPIs(f, nil); err == nil {
		t.Fatal("empty controller list accepted")
	}
	if b, _ := os.ReadFile(f); string(b) != orig {
		t.Fatalf("identity file modified: %s", b)
	}
}

func TestPersistZtAPIs_FiltersAndSkipsUnchanged(t *testing.T) {
	f := filepath.Join(t.TempDir(), "identity.json")
	orig := `{"ztAPI":"https://ctrl:443","ztAPIs":["https://ctrl:443"]}`
	if err := os.WriteFile(f, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}

	// Only unacceptable entries: refused, file untouched.
	bad := []string{"http://ctrl:80", "https://user:pw@ctrl:443", "https://ctrl:443/?x=1", "https://:443", "::"}
	if err := PersistZtAPIs(f, bad); err == nil {
		t.Fatal("list with no acceptable URL accepted")
	}
	if b, _ := os.ReadFile(f); string(b) != orig {
		t.Fatalf("identity file modified: %s", b)
	}

	// Same list as stored (after dedupe/filter): no rewrite.
	before, _ := os.Stat(f)
	if err := PersistZtAPIs(f, []string{"https://ctrl:443", "http://evil", "https://ctrl:443"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != orig {
		t.Fatalf("unchanged list rewrote the file: %s", b)
	}
	after, _ := os.Stat(f)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("file rewritten for an unchanged list")
	}

	// New list: invalid entries dropped, duplicates removed.
	if err := PersistZtAPIs(f, []string{"https://a:443", "ftp://b", "https://a:443", "https://c:1280"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), `"https://a:443",`) || !strings.Contains(string(b), `"https://c:1280"`) ||
		strings.Contains(string(b), "ftp://") || strings.Count(string(b), "https://a:443") != 1 {
		t.Fatalf("unexpected ztAPIs: %s", b)
	}
}
