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
	"fmt"
	"time"
)

// ClaimAccount records an existing Linux account as owned by zitiIdentity in
// reg, so ziti-ssh-host will manage it on that identity's next connection.
// It is the migration path for accounts created by releases that predate the
// ownership registry.
//
// The account must exist, have a valid non-reserved name, and have a UID of at
// least MinManagedUID. Claiming an account already registered to the same
// identity and UID is a no-op; one registered to a different identity, or
// with a different UID, is an error.
//
// The caller is responsible for checking that username is the username derived
// from zitiIdentity.
func ClaimAccount(reg *OwnerRegistry, username, zitiIdentity string) (OwnerRecord, error) {
	return claimAccount(reg, osAccountOps{}, username, zitiIdentity)
}

func claimAccount(reg *OwnerRegistry, ops accountOps, username, zitiIdentity string) (OwnerRecord, error) {
	if zitiIdentity == "" {
		return OwnerRecord{}, fmt.Errorf("identity is empty")
	}
	if err := ValidateManagedUsername(username); err != nil {
		return OwnerRecord{}, err
	}
	uid, exists, err := ops.LookupUID(username)
	if err != nil {
		return OwnerRecord{}, err
	}
	if !exists {
		return OwnerRecord{}, fmt.Errorf("account %q does not exist (nothing to claim; it will be created on first connect)", username)
	}
	if uid < MinManagedUID {
		return OwnerRecord{}, fmt.Errorf("account %q has uid %d, below %d: system accounts cannot be claimed", username, uid, MinManagedUID)
	}
	if rec, ok, err := reg.Get(username); err != nil {
		return OwnerRecord{}, err
	} else if ok {
		if rec.Identity == zitiIdentity && rec.UID == uid {
			return rec, nil
		}
		return OwnerRecord{}, fmt.Errorf("account %q is already registered to identity %q with uid %d", username, rec.Identity, rec.UID)
	}
	rec := OwnerRecord{Identity: zitiIdentity, UID: uid, Created: time.Now().UTC(), Claimed: true}
	if err := reg.Put(username, rec); err != nil {
		return OwnerRecord{}, err
	}
	return rec, nil
}

// LookupAccountUID returns the UID of username via NSS (getent) and whether
// the account exists.
func LookupAccountUID(username string) (int, bool, error) {
	return osAccountOps{}.LookupUID(username)
}
