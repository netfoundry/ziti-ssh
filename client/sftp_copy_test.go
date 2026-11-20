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
	"time"

	"github.com/pkg/sftp"
)

func writeLocal(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readLocal(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpload_FileAndRecursiveDir(t *testing.T) {
	c := memSFTP(t)
	src := t.TempDir()
	writeLocal(t, filepath.Join(src, "one.txt"), "one")
	writeLocal(t, filepath.Join(src, "tree", "a.txt"), "a")
	writeLocal(t, filepath.Join(src, "tree", "sub", "b.txt"), "b")
	if err := c.Mkdir("/dst"); err != nil {
		t.Fatal(err)
	}

	// Single file into an existing directory.
	if err := uploadAll(c, []string{filepath.Join(src, "one.txt")}, "/dst", false, false, true); err != nil {
		t.Fatal(err)
	}
	// Directory without -r is refused.
	if err := uploadAll(c, []string{filepath.Join(src, "tree")}, "/dst", false, false, true); err == nil ||
		!strings.Contains(err.Error(), "use -r") {
		t.Fatalf("directory without -r: %v", err)
	}
	// Recursive directory.
	if err := uploadAll(c, []string{filepath.Join(src, "tree")}, "/dst", true, false, true); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{"/dst/one.txt": "one", "/dst/tree/a.txt": "a", "/dst/tree/sub/b.txt": "b"} {
		f, err := c.Open(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		b := make([]byte, 16)
		n, _ := f.Read(b)
		f.Close()
		if string(b[:n]) != want {
			t.Errorf("%s = %q, want %q", p, b[:n], want)
		}
	}
}

func TestUpload_MultipleSourcesNeedDirectory(t *testing.T) {
	c := memSFTP(t)
	src := t.TempDir()
	writeLocal(t, filepath.Join(src, "a"), "a")
	writeLocal(t, filepath.Join(src, "b"), "b")
	srcs := []string{filepath.Join(src, "a"), filepath.Join(src, "b")}
	if err := uploadAll(c, srcs, "/not-a-dir", false, false, true); err == nil ||
		!strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("multiple sources to a file: %v", err)
	}
	if err := c.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	if err := uploadAll(c, srcs, "/d", false, false, true); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/d/a", "/d/b"} {
		if _, err := c.Stat(p); err != nil {
			t.Errorf("%s missing: %v", p, err)
		}
	}
}

func TestDownload_FileDirAndErrors(t *testing.T) {
	c := memSFTP(t)
	if err := c.MkdirAll("/r/tree/sub"); err != nil {
		t.Fatal(err)
	}
	writeRemote(t, c, "/r/file.txt", "file")
	writeRemote(t, c, "/r/tree/a.txt", "a")
	writeRemote(t, c, "/r/tree/sub/b.txt", "b")
	dst := t.TempDir()

	if err := downloadAll(c, []string{"/r/file.txt"}, dst, false, false, true); err != nil {
		t.Fatal(err)
	}
	if got := readLocal(t, filepath.Join(dst, "file.txt")); got != "file" {
		t.Errorf("file.txt = %q", got)
	}
	// Single file to an explicit new file name.
	if err := downloadAll(c, []string{"/r/file.txt"}, filepath.Join(dst, "renamed"), false, false, true); err != nil {
		t.Fatal(err)
	}
	if got := readLocal(t, filepath.Join(dst, "renamed")); got != "file" {
		t.Errorf("renamed = %q", got)
	}
	if err := downloadAll(c, []string{"/r/tree"}, dst, false, false, true); err == nil ||
		!strings.Contains(err.Error(), "use -r") {
		t.Fatalf("remote directory without -r: %v", err)
	}
	if err := downloadAll(c, []string{"/r/tree"}, dst, true, false, true); err != nil {
		t.Fatal(err)
	}
	if got := readLocal(t, filepath.Join(dst, "tree", "sub", "b.txt")); got != "b" {
		t.Errorf("tree/sub/b.txt = %q", got)
	}
	if err := downloadAll(c, []string{"/r/missing"}, dst, false, false, true); err == nil {
		t.Fatal("missing remote path accepted")
	}
	if err := downloadAll(c, []string{"/r/file.txt", "/r/tree/a.txt"}, filepath.Join(dst, "renamed"), false, false, true); err == nil ||
		!strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("multiple sources to a file: %v", err)
	}
}

// fsSFTP returns a client for an SFTP server backed by the real filesystem
// (the in-memory server does not keep timestamps).
func fsSFTP(t *testing.T) *sftp.Client {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	server, err := sftp.NewServer(srvConn)
	if err != nil {
		t.Fatal(err)
	}
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

func TestPreserveTimes_UploadAndDownload(t *testing.T) {
	c := fsSFTP(t)
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	dir := t.TempDir()

	// Upload with -p: the remote file gets the local mtime.
	src := filepath.Join(dir, "src")
	writeLocal(t, src, "x")
	if err := os.Chtimes(src, when, when); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(dir, "remote")
	if err := uploadAll(c, []string{src}, remote, false, true, true); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(remote); err != nil || !st.ModTime().Equal(when) {
		t.Errorf("upload -p: mtime %v, %v; want %v", st.ModTime(), err, when)
	}

	// Download with -p: the local file gets the remote mtime.
	local := filepath.Join(dir, "local")
	if err := downloadAll(c, []string{remote}, local, false, true, true); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(local); err != nil || !st.ModTime().Equal(when) {
		t.Errorf("download -p: mtime %v, %v; want %v", st.ModTime(), err, when)
	}

	// Without -p the time is not copied.
	plain := filepath.Join(dir, "plain")
	if err := downloadAll(c, []string{remote}, plain, false, false, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(plain); st.ModTime().Equal(when) {
		t.Error("mtime copied without -p")
	}
}

func TestSafeName(t *testing.T) {
	for _, ok := range []string{"a", "file.txt", ".hidden", "a..b"} {
		if err := safeName(ok); err != nil {
			t.Errorf("safeName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`, "../x", "/abs"} {
		if err := safeName(bad); err == nil {
			t.Errorf("safeName(%q) accepted", bad)
		}
	}
}
