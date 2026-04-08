package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// PersistZtAPIs atomically overwrites the ztAPIs field in the given Ziti
// identity JSON file with urls. The write is atomic (write to a sibling temp
// file then rename) so a concurrent reader never sees a partial update.
//
// Call this from an EventControllerUrlsUpdated listener so that the full
// cluster member list is persisted after each controller discovery. Without
// this, the identity file only ever contains the originally enrolled
// controller URL, meaning a process restart fails if that specific controller
// is offline (even if other cluster members are healthy).
func PersistZtAPIs(identityFile string, urls []string) error {
	data, err := os.ReadFile(identityFile)
	if err != nil {
		return fmt.Errorf("read identity file: %w", err)
	}

	// Parse as a generic map so that fields we don't know about (e.g. cert/key
	// PEM stored under "id") are preserved verbatim.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse identity file: %w", err)
	}

	encoded, err := json.Marshal(urls)
	if err != nil {
		return fmt.Errorf("marshal ztAPIs: %w", err)
	}
	raw["ztAPIs"] = json.RawMessage(encoded)

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	// Preserve the original file mode.
	fi, err := os.Stat(identityFile)
	mode := os.FileMode(0600)
	if err == nil {
		mode = fi.Mode()
	}

	tmp := identityFile + ".tmp"
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return fmt.Errorf("write temp identity file: %w", err)
	}
	if err := os.Rename(tmp, identityFile); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp identity file: %w", err)
	}
	return nil
}
