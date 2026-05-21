// Package client — SFTP file copy helper for ziti-scp.
//
// RunSFTP establishes an SSH client connection over an existing net.Conn
// (already dialled via the Ziti overlay), opens an SFTP subsystem session,
// and copies files between local and remote paths. It supports upload
// (local → remote) and download (remote → local), with optional recursive
// directory copy and preserve mode (timestamps + permissions). Progress is
// printed to stderr in an scp-style format.
package client

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// RunSFTP copies files between local and remote endpoints over an already-dialled
// Ziti net.Conn.
//
// srcArgs is the list of source specifications (each may be "[user@]host:path" or
// a local path). dst is the destination specification. The caller resolves which
// side is remote before calling RunSFTP; isUpload indicates direction:
//   - isUpload == true: srcArgs are local paths, dstRemotePath is the remote path.
//   - isUpload == false: srcArgs are remote paths, dstLocalPath is the local path.
//
// The SSH connection is established with user/host as given. signer provides the
// credential (typically an ssh.CertSigner). recursive enables directory recursion.
// preserve copies file timestamps and permissions. quiet suppresses progress output.
func RunSFTP(
	conn net.Conn,
	user, host string,
	signer ssh.Signer,
	isUpload bool,
	localPaths []string,
	remotePath string,
	recursive bool,
	preserve bool,
	quiet bool,
) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// Host key verification is intentionally skipped. The connection arrives
		// over a Ziti overlay that enforces mutual TLS using the controller's
		// PKI — the host's Ziti identity is cryptographically proven before any
		// SSH bytes are exchanged. A traditional known-hosts check would be
		// redundant and weaker than the guarantee Ziti already provides.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		return fmt.Errorf("SSH handshake with %q: %w", host, err)
	}
	sshClient := ssh.NewClient(clientConn, chans, reqs)
	defer sshClient.Close()

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("open SFTP subsystem: %w", err)
	}
	defer sftpClient.Close()

	if isUpload {
		return uploadAll(sftpClient, localPaths, remotePath, recursive, preserve, quiet)
	}
	return downloadAll(sftpClient, localPaths, remotePath, recursive, preserve, quiet)
}

// ---------------------------------------------------------------------------
// Upload (local → remote)
// ---------------------------------------------------------------------------

func uploadAll(client *sftp.Client, localPaths []string, remoteDst string, recursive, preserve, quiet bool) error {
	// Determine whether the destination is (or should be) a directory.
	// We need this to know whether to place files inside it or overwrite it.
	dstIsDir := false
	if fi, err := client.Stat(remoteDst); err == nil {
		dstIsDir = fi.IsDir()
	}

	// Multiple sources always require a directory destination.
	if len(localPaths) > 1 && !dstIsDir {
		return fmt.Errorf("remote destination %q must be a directory when copying multiple sources", remoteDst)
	}

	for _, localPath := range localPaths {
		fi, err := os.Stat(localPath)
		if err != nil {
			return fmt.Errorf("stat %q: %w", localPath, err)
		}
		if fi.IsDir() {
			if !recursive {
				return fmt.Errorf("%q is a directory; use -r to copy recursively", localPath)
			}
			var dstDir string
			if dstIsDir {
				dstDir = path.Join(remoteDst, filepath.Base(localPath))
			} else {
				dstDir = remoteDst
			}
			if err := uploadDir(client, localPath, dstDir, preserve, quiet); err != nil {
				return err
			}
		} else {
			var dstFile string
			if dstIsDir {
				dstFile = path.Join(remoteDst, filepath.Base(localPath))
			} else {
				dstFile = remoteDst
			}
			if err := uploadFile(client, localPath, dstFile, preserve, quiet); err != nil {
				return err
			}
		}
	}
	return nil
}

func uploadDir(client *sftp.Client, localDir, remoteDir string, preserve, quiet bool) error {
	if err := client.MkdirAll(remoteDir); err != nil {
		return fmt.Errorf("mkdir remote %q: %w", remoteDir, err)
	}

	entries, err := os.ReadDir(localDir)
	if err != nil {
		return fmt.Errorf("read local dir %q: %w", localDir, err)
	}

	for _, entry := range entries {
		localPath := filepath.Join(localDir, entry.Name())
		remotePath := path.Join(remoteDir, entry.Name())
		if entry.IsDir() {
			if err := uploadDir(client, localPath, remotePath, preserve, quiet); err != nil {
				return err
			}
		} else {
			if err := uploadFile(client, localPath, remotePath, preserve, quiet); err != nil {
				return err
			}
		}
	}

	if preserve {
		fi, err := os.Stat(localDir)
		if err == nil {
			_ = client.Chtimes(remoteDir, fi.ModTime(), fi.ModTime())
		}
	}
	return nil
}

func uploadFile(client *sftp.Client, localPath, remotePath string, preserve, quiet bool) error {
	src, err := os.Open(localPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open local file %q: %w", localPath, err)
	}
	defer src.Close()

	fi, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat local file %q: %w", localPath, err)
	}

	var perm os.FileMode = 0644
	if preserve {
		perm = fi.Mode().Perm()
	}

	dst, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open remote file %q for writing: %w", remotePath, err)
	}
	defer dst.Close()

	if err := dst.Chmod(perm); err != nil {
		slog.Debug("chmod remote file failed (non-fatal)", "path", remotePath, "err", err)
	}

	var w io.Writer = dst
	if !quiet {
		w = &progressWriter{
			w:         dst,
			name:      filepath.Base(localPath),
			total:     fi.Size(),
			lastPrint: time.Now(),
		}
	}

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("copy to remote %q: %w", remotePath, err)
	}

	if !quiet {
		printFinalProgress(filepath.Base(localPath), fi.Size())
	}

	if preserve {
		_ = client.Chtimes(remotePath, fi.ModTime(), fi.ModTime())
	}
	return nil
}

// ---------------------------------------------------------------------------
// Download (remote → local)
// ---------------------------------------------------------------------------

func downloadAll(client *sftp.Client, remotePaths []string, localDst string, recursive, preserve, quiet bool) error {
	// Determine whether the local destination is a directory.
	dstIsDir := false
	if fi, err := os.Stat(localDst); err == nil {
		dstIsDir = fi.IsDir()
	}

	if len(remotePaths) > 1 && !dstIsDir {
		return fmt.Errorf("local destination %q must be a directory when copying multiple sources", localDst)
	}

	for _, remotePath := range remotePaths {
		fi, err := client.Stat(remotePath)
		if err != nil {
			return fmt.Errorf("stat remote %q: %w", remotePath, err)
		}
		if fi.IsDir() {
			if !recursive {
				return fmt.Errorf("remote %q is a directory; use -r to copy recursively", remotePath)
			}
			var localDir string
			if dstIsDir {
				localDir = filepath.Join(localDst, path.Base(remotePath))
			} else {
				localDir = localDst
			}
			if err := downloadDir(client, remotePath, localDir, preserve, quiet); err != nil {
				return err
			}
		} else {
			var localFile string
			if dstIsDir {
				localFile = filepath.Join(localDst, path.Base(remotePath))
			} else {
				localFile = localDst
			}
			if err := downloadFile(client, remotePath, localFile, preserve, quiet); err != nil {
				return err
			}
		}
	}
	return nil
}

func downloadDir(client *sftp.Client, remoteDir, localDir string, preserve, quiet bool) error {
	fi, err := client.Stat(remoteDir)
	if err != nil {
		return fmt.Errorf("stat remote dir %q: %w", remoteDir, err)
	}

	var perm os.FileMode = 0755
	if preserve {
		perm = fi.Mode().Perm()
	}
	if err := os.MkdirAll(localDir, perm); err != nil {
		return fmt.Errorf("mkdir local %q: %w", localDir, err)
	}

	entries, err := client.ReadDir(remoteDir)
	if err != nil {
		return fmt.Errorf("read remote dir %q: %w", remoteDir, err)
	}

	for _, entry := range entries {
		if err := safeName(entry.Name()); err != nil {
			return fmt.Errorf("remote dir %q: %w", remoteDir, err)
		}
		rPath := path.Join(remoteDir, entry.Name())
		lPath := filepath.Join(localDir, entry.Name())
		if entry.IsDir() {
			if err := downloadDir(client, rPath, lPath, preserve, quiet); err != nil {
				return err
			}
		} else {
			if err := downloadFile(client, rPath, lPath, preserve, quiet); err != nil {
				return err
			}
		}
	}

	if preserve {
		_ = os.Chtimes(localDir, fi.ModTime(), fi.ModTime())
	}
	return nil
}

func downloadFile(client *sftp.Client, remotePath, localPath string, preserve, quiet bool) error {
	src, err := client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file %q: %w", remotePath, err)
	}
	defer src.Close()

	fi, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat remote file %q: %w", remotePath, err)
	}

	var perm os.FileMode = 0644
	if preserve {
		perm = fi.Mode().Perm()
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("create local parent dir for %q: %w", localPath, err)
	}

	dst, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open local file %q for writing: %w", localPath, err)
	}
	defer dst.Close()

	var w io.Writer = dst
	if !quiet {
		w = &progressWriter{
			w:         dst,
			name:      path.Base(remotePath),
			total:     fi.Size(),
			lastPrint: time.Now(),
		}
	}

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("copy from remote %q: %w", remotePath, err)
	}

	if !quiet {
		printFinalProgress(path.Base(remotePath), fi.Size())
	}

	if preserve {
		_ = os.Chtimes(localPath, fi.ModTime(), fi.ModTime())
	}
	return nil
}

// safeName rejects remote-supplied entry names that could escape the local
// download target via path traversal (e.g. "..", "../etc/passwd", or names
// embedding a path separator).
func safeName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("rejected unsafe remote entry name %q", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("rejected unsafe remote entry name %q", name)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Progress reporting
// ---------------------------------------------------------------------------

// progressWriter wraps an io.Writer and prints scp-style progress to stderr.
type progressWriter struct {
	w         io.Writer
	name      string
	total     int64
	written   int64
	lastPrint time.Time
	start     time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	pw.written += int64(n)
	if pw.start.IsZero() {
		pw.start = time.Now()
	}
	now := time.Now()
	if now.Sub(pw.lastPrint) >= 500*time.Millisecond {
		pw.printProgress(now)
		pw.lastPrint = now
	}
	return n, err
}

func (pw *progressWriter) printProgress(now time.Time) {
	elapsed := now.Sub(pw.start)
	if elapsed == 0 {
		elapsed = time.Millisecond
	}
	speedBytesPerSec := float64(pw.written) / elapsed.Seconds()

	pct := 0
	if pw.total > 0 {
		pct = int(pw.written * 100 / pw.total)
	}

	remaining := pw.total - pw.written
	var etaSec float64
	if speedBytesPerSec > 0 {
		etaSec = float64(remaining) / speedBytesPerSec
	}
	eta := time.Duration(etaSec) * time.Second

	name := pw.name
	if len(name) > 30 {
		name = "..." + name[len(name)-27:]
	}

	fmt.Fprintf(os.Stderr, "\r%-30s %3d%%  %s  %s/s  %s   ",
		name,
		pct,
		formatBytes(pw.written),
		formatBytesRate(speedBytesPerSec),
		formatDuration(eta),
	)
}

func printFinalProgress(name string, total int64) {
	if len(name) > 30 {
		name = "..." + name[len(name)-27:]
	}
	fmt.Fprintf(os.Stderr, "\r%-30s 100%%  %s                    \n",
		name,
		formatBytes(total),
	)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatBytesRate(bytesPerSec float64) string {
	return formatBytes(int64(bytesPerSec)) + "/s"
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}
