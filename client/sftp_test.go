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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

// memSFTP returns a client connected to an in-memory SFTP server.
func memSFTP(t *testing.T) *sftp.Client {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	server := sftp.NewRequestServer(srvConn, sftp.InMemHandler())
	go func() { _ = server.Serve() }()
	c, err := sftp.NewClientPipe(cliConn, cliConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		server.Close()
	})
	return c
}

func writeRemote(t *testing.T, c *sftp.Client, p, content string) {
	t.Helper()
	f, err := c.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestDownload_RefusesToWriteThroughLocalSymlink(t *testing.T) {
	c := memSFTP(t)
	if err := c.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	writeRemote(t, c, "/d/notes", "from the server")

	local := t.TempDir()
	victim := filepath.Join(local, "startup-file")
	if err := os.WriteFile(victim, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(local, "d")
	if err := os.Mkdir(dst, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dst, "notes")); err != nil {
		t.Fatal(err)
	}

	err := downloadDir(c, "/d", dst, false, true, 0)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want symlink refusal, got %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Fatalf("file behind the symlink was overwritten: %q", b)
	}
}

func TestDownload_DepthLimit(t *testing.T) {
	c := memSFTP(t)
	if err := c.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	err := downloadDir(c, "/d", filepath.Join(t.TempDir(), "d"), false, true, maxRecursionDepth+1)
	if err == nil || !strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("want depth limit error, got %v", err)
	}
}

// File modes are tested through downloadMode: the in-memory SFTP server used
// here always reports files as 0644, so it cannot exercise remote modes.
func TestDownloadMode(t *testing.T) {
	cases := []struct {
		remote   os.FileMode
		preserve bool
		want     os.FileMode
	}{
		{0o600, false, 0o600},
		{0o777, false, 0o777}, // reduced by umask when the file is created
		{0o777, true, 0o775},  // -p: never world-writable
		{os.ModeSetuid | os.ModeSticky | 0o755, true, 0o755},
	}
	for _, c := range cases {
		if got := downloadMode(c.remote, c.preserve); got != c.want {
			t.Errorf("downloadMode(%v, %v) = %o, want %o", c.remote, c.preserve, got, c.want)
		}
	}
}

func TestTerminalSafe(t *testing.T) {
	in := "report\x1b]0;pwned\x07\x9b2J.txt"
	got := terminalSafe(in)
	if strings.ContainsAny(got, "\x1b\x07") || strings.ContainsRune(got, 0x9b) {
		t.Errorf("control characters survived: %q", got)
	}
	if !strings.HasPrefix(got, "report") || !strings.HasSuffix(got, ".txt") {
		t.Errorf("printable text altered: %q", got)
	}
}
