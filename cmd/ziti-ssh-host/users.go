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
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/netfoundry/ziti-ssh/ca"
	"github.com/netfoundry/ziti-ssh/host"
)

// ownerRegistry returns the registry used by "run" in per-identity mode.
func ownerRegistry() *host.OwnerRegistry {
	return host.NewOwnerRegistry(filepath.Join(filepath.Dir(userManagerStateFile), host.OwnedUsersFileName))
}

// newUsersCmd builds the "users" subcommand group for administering the
// per-identity account ownership registry.
func newUsersCmd() *cobra.Command {
	usersCmd := &cobra.Command{
		Use:   "users",
		Short: "Administer per-identity Linux accounts managed by ziti-ssh-host",
	}

	listCmd := &cobra.Command{
		Use:          "list",
		Short:        "List accounts in the ownership registry (requires root)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := ownerRegistry()
			names, entries, err := reg.List()
			if err != nil {
				return err
			}
			if len(names) == 0 {
				fmt.Printf("No accounts registered in %s\n", reg.Path())
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "USERNAME\tZITI IDENTITY\tUID\tCREATED\tSOURCE\tSTATUS")
			for _, n := range names {
				rec := entries[n]
				source := "created"
				if rec.Claimed {
					source = "claimed"
				}
				status := "ok"
				uid, exists, err := host.LookupAccountUID(n)
				switch {
				case err != nil:
					status = "lookup error: " + err.Error()
				case !exists:
					status = "account missing (record removed on next disconnect or recreated on connect)"
				case uid != rec.UID:
					status = fmt.Sprintf("UID MISMATCH (now %d): account will not be managed", uid)
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n", n, rec.Identity, rec.UID, rec.Created.Format(time.RFC3339), source, status)
			}
			return w.Flush()
		},
	}

	var claimUsername, claimIdentity string
	claimCmd := &cobra.Command{
		Use:   "claim",
		Short: "Register an existing account as owned by a Ziti identity (requires root)",
		Long: `Register an existing Linux account in the ownership registry so that
ziti-ssh-host manages it for the given Ziti identity.

ziti-ssh-host only creates, modifies, or deletes accounts recorded in its
ownership registry. Accounts created by releases before the registry existed
are therefore refused until claimed. --username must be the username derived
from --identity, and the account must have a UID of at least 1000.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if claimUsername == "" || claimIdentity == "" {
				return fmt.Errorf("--username and --identity are required")
			}
			if derived := ca.DeriveUsername(claimIdentity); derived != claimUsername {
				return fmt.Errorf("identity %q derives username %q, not %q", claimIdentity, derived, claimUsername)
			}
			rec, err := host.ClaimAccount(ownerRegistry(), claimUsername, claimIdentity)
			if err != nil {
				return err
			}
			fmt.Printf("Registered %s (uid %d) to Ziti identity %q\n", claimUsername, rec.UID, rec.Identity)
			return nil
		},
	}
	claimCmd.Flags().StringVar(&claimUsername, "username", "", "Existing Linux username to claim")
	claimCmd.Flags().StringVar(&claimIdentity, "identity", "", "Ziti identity name that owns the account")

	usersCmd.AddCommand(listCmd, claimCmd)
	return usersCmd
}
