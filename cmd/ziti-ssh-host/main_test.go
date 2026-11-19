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

import (
	"errors"
	"testing"

	"github.com/netfoundry/ziti-ssh/host"
)

func TestServiceState_FailsClosedOnLoadErrors(t *testing.T) {
	var st serviceState
	good := &host.PermissionsConfig{Permissions: map[string]host.IdentityPermissions{"alice": {Groups: []string{"dev"}}}}

	// Startup load failure: unavailable, not "fall back to globals".
	st.update(nil, errors.New("parse error"))
	if _, err := st.current(); err == nil {
		t.Fatal("failed initial load not reported")
	}

	// A good load makes the service available.
	st.update(good, nil)
	if pc, err := st.current(); err != nil || pc != good {
		t.Fatalf("good load: pc=%v err=%v", pc, err)
	}

	// A failed reload must not keep the previous (possibly broader) config.
	st.update(nil, errors.New("bad entry"))
	if pc, err := st.current(); err == nil || pc != nil {
		t.Fatalf("failed reload kept old config: pc=%v err=%v", pc, err)
	}

	// No config attached is not an error: global fallbacks apply.
	st.update(nil, nil)
	if pc, err := st.current(); err != nil || pc != nil {
		t.Fatalf("no config attached: pc=%v err=%v", pc, err)
	}
}
