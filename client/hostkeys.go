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

package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Host key trust on first use.
//
// OpenZiti does not tell a dialer which identity answered on a terminator
// address, so ziti-ssh cannot verify a host's identity. Instead it remembers
// the SSH host key(s) seen for each Ziti address and detects changes:
//
//   - address dialed by terminator name ("<terminator>@<service>"), i.e. one
//     host: an unknown address is trusted and saved; a different key is
//     refused (remove the entry with "ziti-ssh known-hosts remove" after a
//     legitimate rebuild).
//   - service dialed by name ("<service>"), where any host bound to the
//     service may answer: an unknown address is trusted and saved; a
//     different key is shown with a warning and, if the user agrees, saved as
//     an additional key for that service. Without a terminal it is refused.

// KnownHostsAddress returns the address under which host keys are recorded:
// "<terminator>@<service>" for a terminator dial, or "<service>" when the
// service is dialed directly (any host bound to it may answer).
func KnownHostsAddress(service, terminator string) string {
	if terminator == "" {
		return service
	}
	return terminator + "@" + service
}

// DefaultKnownHostsPath returns $XDG_CONFIG_HOME/ziti-ssh/known_hosts
// (default ~/.config/ziti-ssh/known_hosts).
func DefaultKnownHostsPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "ziti-ssh", "known_hosts"), nil
}

// KnownHosts is a file of "<address> <key-type> <base64-key>" lines (the
// OpenSSH known_hosts line format, with Ziti addresses instead of hostnames).
type KnownHosts struct {
	Path string
}

type knownHostEntry struct {
	addr string
	key  ssh.PublicKey
}

func (k KnownHosts) read() ([]knownHostEntry, error) {
	data, err := os.ReadFile(k.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", k.Path, err)
	}
	var out []knownHostEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		addr, rest, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("%s:%d: malformed entry", k.Path, n)
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(rest)))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", k.Path, n, err)
		}
		out = append(out, knownHostEntry{addr: addr, key: key})
	}
	return out, sc.Err()
}

func (k KnownHosts) write(entries []knownHostEntry) error {
	var b strings.Builder
	b.WriteString("# ziti-ssh known host keys: <ziti address> <key>\n")
	for _, e := range entries {
		b.WriteString(e.addr)
		b.WriteByte(' ')
		b.Write(bytes.TrimSpace(ssh.MarshalAuthorizedKey(e.key)))
		b.WriteByte('\n')
	}
	dir := filepath.Dir(k.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".known_hosts-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// Atomic replace. Concurrent ziti-ssh processes may race; the worst case
	// is a lost entry, which is re-learned on the next connection.
	if err := os.Rename(tmpPath, k.Path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", k.Path, err)
	}
	return nil
}

// Keys returns the keys recorded for addr.
func (k KnownHosts) Keys(addr string) ([]ssh.PublicKey, error) {
	entries, err := k.read()
	if err != nil {
		return nil, err
	}
	var out []ssh.PublicKey
	for _, e := range entries {
		if e.addr == addr {
			out = append(out, e.key)
		}
	}
	return out, nil
}

// Add records key for addr (no-op if already present).
func (k KnownHosts) Add(addr string, key ssh.PublicKey) error {
	entries, err := k.read()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.addr == addr && bytes.Equal(e.key.Marshal(), key.Marshal()) {
			return nil
		}
	}
	return k.write(append(entries, knownHostEntry{addr: addr, key: key}))
}

// Remove deletes every key recorded for addr and returns how many it removed.
func (k KnownHosts) Remove(addr string) (int, error) {
	entries, err := k.read()
	if err != nil {
		return 0, err
	}
	kept := entries[:0]
	removed := 0
	for _, e := range entries {
		if e.addr == addr {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, k.write(kept)
}

// List writes "<address> <type> <SHA256 fingerprint>" for every entry,
// sorted by address.
func (k KnownHosts) List(w io.Writer) error {
	entries, err := k.read()
	if err != nil {
		return err
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].addr < entries[j].addr })
	for _, e := range entries {
		fmt.Fprintf(w, "%s %s %s\n", e.addr, e.key.Type(), ssh.FingerprintSHA256(e.key))
	}
	return nil
}

// HostKeyPolicy configures HostKeyCallback.
type HostKeyPolicy struct {
	Store KnownHosts
	// Address is the Ziti address dialed (see KnownHostsAddress).
	Address string
	// MultiHost is true when the service was dialed directly, so any host
	// bound to it may answer and several keys may be legitimate.
	MultiHost bool
	// Confirm asks the user a yes/no question; nil means non-interactive.
	Confirm func(question string) bool
	// Notify receives informational and warning messages (normally stderr).
	Notify io.Writer
}

// HostKeyCallback returns an ssh.HostKeyCallback implementing trust on first
// use for p.Address (see the package comment above).
func HostKeyCallback(p HostKeyPolicy) ssh.HostKeyCallback {
	notify := p.Notify
	if notify == nil {
		notify = io.Discard
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		known, err := p.Store.Keys(p.Address)
		if err != nil {
			return fmt.Errorf("known hosts: %w", err)
		}
		for _, k := range known {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				return nil
			}
		}
		fp := ssh.FingerprintSHA256(key)
		if len(known) == 0 {
			if err := p.Store.Add(p.Address, key); err != nil {
				return fmt.Errorf("known hosts: %w", err)
			}
			fmt.Fprintf(notify, "Permanently added host key for %s (%s %s) to %s\n", p.Address, key.Type(), fp, p.Store.Path)
			return nil
		}

		var prints []string
		for _, k := range known {
			prints = append(prints, k.Type()+" "+ssh.FingerprintSHA256(k))
		}
		if !p.MultiHost {
			fmt.Fprintf(notify, "@@@ WARNING: HOST KEY FOR %s HAS CHANGED @@@\n"+
				"Someone could be impersonating this host, or it may have been rebuilt.\n"+
				"  known:    %s\n  received: %s %s\n"+
				"If the change is expected, run: ziti-ssh known-hosts remove %s\n",
				p.Address, strings.Join(prints, ", "), key.Type(), fp, p.Address)
			return fmt.Errorf("host key for %s has changed; refusing to connect", p.Address)
		}

		msg := fmt.Sprintf("WARNING: service %s answered with a host key not seen before.\n"+
			"Any host bound to the service may answer, so this may be another member of the pool,\n"+
			"or someone impersonating one.\n  known:    %s\n  received: %s %s\n",
			p.Address, strings.Join(prints, ", "), key.Type(), fp)
		fmt.Fprint(notify, msg)
		if p.Confirm == nil {
			return fmt.Errorf("new host key for service %s; run ziti-ssh interactively once to review and accept it", p.Address)
		}
		if !p.Confirm(fmt.Sprintf("Trust this additional key for %s? [y/N] ", p.Address)) {
			return fmt.Errorf("host key for service %s not accepted", p.Address)
		}
		if err := p.Store.Add(p.Address, key); err != nil {
			return fmt.Errorf("known hosts: %w", err)
		}
		fmt.Fprintf(notify, "Added additional host key for %s (%s %s)\n", p.Address, key.Type(), fp)
		return nil
	}
}

// NewHostKeyCallback returns the host-key check for a connection to service
// (and terminator, empty for a direct service dial), using the default known
// hosts file. It asks on the terminal before trusting an additional key for a
// directly dialed service, and only when stdin and stderr are terminals.
func NewHostKeyCallback(service, terminator string) (ssh.HostKeyCallback, error) {
	path, err := DefaultKnownHostsPath()
	if err != nil {
		return nil, err
	}
	p := HostKeyPolicy{
		Store:     KnownHosts{Path: path},
		Address:   KnownHostsAddress(service, terminator),
		MultiHost: terminator == "",
		Notify:    os.Stderr,
	}
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())) {
		p.Confirm = func(question string) bool {
			fmt.Fprint(os.Stderr, question)
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
		}
	}
	return HostKeyCallback(p), nil
}
