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
