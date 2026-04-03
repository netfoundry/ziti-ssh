// Package client provides SSH session helpers for the ziti-ssh CLI.
//
// Four exported functions cover the lifecycle of a certificate-backed SSH
// session over a pre-dialed net.Conn:
//
//   - NewCertSigner   — loads a private key and, if a matching -cert.pub file
//     exists, wraps it in an ssh.CertSigner so the certificate
//     is presented during authentication.
//
//   - CertNeedsRefresh — returns true when the cert file is missing or will
//     expire within 30 minutes.
//
//   - RunSession       — runs a full interactive SSH session with PTY over a
//     net.Conn that has already been dialled (e.g. via ziti.Dial).
//
//   - RunCommand       — runs a single non-interactive remote command over a
//     net.Conn that has already been dialled. No PTY is allocated.
//     The remote exit code is propagated via os.Exit.
package client

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)


// NewCertSigner loads the SSH private key at keyPath and, if a corresponding
// certificate file (<keyPath>-cert.pub) is present on disk, wraps the signer
// in an ssh.CertSigner so that the certificate is offered during SSH
// public-key authentication.
//
// If the private key is passphrase-protected, ssh.ParsePrivateKey returns
// *ssh.PassphraseMissingError. In that case NewCertSigner falls back to the
// SSH agent (SSH_AUTH_SOCK): it finds the agent signer whose public key
// matches the key file and, if a valid cert is also present, wraps it in an
// ssh.CertSigner. This lets users with passphrase-protected keys authenticate
// without ever exposing the passphrase to this process.
//
// If the cert file is absent or cannot be parsed the raw signer is returned
// without error — the caller can still authenticate with the bare key.
func NewCertSigner(keyPath string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %q: %w", keyPath, err)
	}

	signer, parseErr := ssh.ParsePrivateKey(keyBytes)
	if parseErr != nil {
		// If the key is passphrase-protected, fall back to the SSH agent.
		var passErr *ssh.PassphraseMissingError
		if !errors.As(parseErr, &passErr) {
			return nil, fmt.Errorf("parse SSH key %q: %w", keyPath, parseErr)
		}

		return newSignerFromAgent(keyPath)
	}

	return wrapWithCert(signer, keyPath)
}

// newSignerFromAgent resolves a signer for keyPath from the SSH agent and,
// if a valid cert file is present, wraps it in an ssh.CertSigner.
func newSignerFromAgent(keyPath string) (ssh.Signer, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return nil, fmt.Errorf("SSH key %q is passphrase-protected and SSH_AUTH_SOCK is not set; "+
			"unlock the key with ssh-add or set SSH_AUTH_SOCK", keyPath)
	}

	agentConn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("SSH key %q is passphrase-protected and connecting to SSH agent failed: %w", keyPath, err)
	}
	// agentConn is intentionally left open for the lifetime of this signer;
	// the agent client holds a reference to it. The OS will reclaim it when
	// the process exits or the signer is GC'd with a finalizer in practice —
	// no explicit close here because the returned signer must remain usable.

	agentClient := agent.NewClient(agentConn)
	signers, err := agentClient.Signers()
	if err != nil {
		_ = agentConn.Close()
		return nil, fmt.Errorf("list SSH agent keys: %w", err)
	}

	// Determine the expected public key bytes by reading the .pub file.
	wantPubBytes, err := pubKeyBytesForKey(keyPath)
	if err != nil {
		_ = agentConn.Close()
		return nil, err
	}

	// Find the agent signer whose public key matches the on-disk key.
	var matched ssh.Signer
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), wantPubBytes) {
			matched = s
			break
		}
	}
	if matched == nil {
		_ = agentConn.Close()
		return nil, fmt.Errorf("SSH key %q is passphrase-protected but no matching key was found in the SSH agent; "+
			"run: ssh-add %s", keyPath, keyPath)
	}

	return wrapWithCert(matched, keyPath)
}

// pubKeyBytesForKey returns the marshalled public key bytes for keyPath.
// It prefers reading the <keyPath>.pub file (OpenSSH convention). If that
// fails and a cert file is present, it extracts the public key from the cert.
func pubKeyBytesForKey(keyPath string) ([]byte, error) {
	pubPath := keyPath + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err == nil {
		pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(bytes.TrimSpace(pubData))
		if parseErr == nil {
			return pub.Marshal(), nil
		}
	}

	// Fall back: try to extract the public key from the cert file.
	certPath := keyPath + "-cert.pub"
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot determine public key for %q: .pub file missing and no cert file found", keyPath)
	}
	pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(certData)
	if parseErr != nil {
		return nil, fmt.Errorf("cannot determine public key for %q: .pub file missing and cert file unreadable: %w", keyPath, parseErr)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("cannot determine public key for %q: .pub file missing and cert file does not contain a certificate", keyPath)
	}
	return cert.Key.Marshal(), nil
}

// wrapWithCert takes a signer and, if a valid cert file exists at
// <keyPath>-cert.pub, returns an ssh.CertSigner wrapping both.
// If the cert file is absent or unparseable the bare signer is returned.
func wrapWithCert(signer ssh.Signer, keyPath string) (ssh.Signer, error) {
	certPath := keyPath + "-cert.pub"
	certData, err := os.ReadFile(certPath)
	if err != nil {
		// No cert file — return the bare signer.
		return signer, nil
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		// Cert file unreadable — caller decides whether that matters.
		return signer, nil
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return signer, nil
	}

	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return signer, nil
	}

	return certSigner, nil
}

// CertNeedsRefresh returns true when the certificate file at certPath is
// either absent or will expire within 30 minutes of the time this function is
// called. It returns false if the file is present and has more than 30 minutes
// of validity remaining.
func CertNeedsRefresh(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		// File missing or unreadable — needs refresh.
		return true
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return true
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return true
	}

	// ValidBefore is a uint64 Unix timestamp. Zero means "forever", but that
	// is not issued by this CA — treat it as always-valid just in case.
	if cert.ValidBefore == 0 || cert.ValidBefore == ssh.CertTimeInfinity {
		return false
	}

	expiry := time.Unix(int64(cert.ValidBefore), 0)
	return time.Until(expiry) < 30*time.Minute
}

// RunSession opens an interactive SSH shell session over conn.
//
// conn must already be a connected net.Conn (e.g. returned by ziti.Dial).
// user is the remote username; host is used only as the hostname passed to
// ssh.NewClientConn (OpenSSH convention — it does not perform DNS resolution
// here). signer provides the public-key / certificate auth credential.
//
// The terminal is placed in raw mode for the duration of the session and
// restored on return (even on error).
//
// Host key verification is intentionally skipped. The connection arrives over
// a Ziti overlay that enforces mutual TLS using the controller's PKI — the
// host's Ziti identity is cryptographically proven before any SSH bytes are
// exchanged. A traditional known-hosts check would be redundant and weaker
// than the guarantee Ziti already provides.
func RunSession(conn net.Conn, user, host string, signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		return fmt.Errorf("SSH handshake with %q: %w", host, err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	// Wire up terminal I/O.
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())

	width, height, err := term.GetSize(stdoutFd)
	if err != nil {
		// Non-fatal: fall back to a sensible default.
		width, height = 80, 24
	}

	// Put the local terminal in raw mode so special characters are passed
	// through to the remote shell rather than handled locally.
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return fmt.Errorf("set terminal raw mode: %w", err)
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	if err := session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request PTY: %w", err)
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start remote shell: %w", err)
	}

	return session.Wait()
}

// RunCommand runs a single non-interactive remote command over conn.
//
// conn must already be a connected net.Conn (e.g. returned by ziti.Dial).
// user is the remote username; host is used only as the hostname passed to
// ssh.NewClientConn (it does not perform DNS resolution here). command is the
// shell command string to execute on the remote host. signer provides the
// public-key / certificate auth credential.
//
// No PTY is allocated. os.Stdin, os.Stdout, and os.Stderr are wired directly
// to the session so the caller can pipe data or capture output normally.
//
// If the remote command exits with a non-zero status, RunCommand calls
// os.Exit with that status code rather than returning an error, matching the
// behaviour of standard ssh(1). Other errors (handshake failure, session
// open failure, etc.) are returned normally so the caller can log them.
//
// Host key verification is intentionally skipped for the same reason as
// RunSession — the Ziti overlay enforces mutual TLS before any SSH bytes are
// exchanged.
func RunCommand(conn net.Conn, user, host, command string, signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		return fmt.Errorf("SSH handshake with %q: %w", host, err)
	}
	c := ssh.NewClient(clientConn, chans, reqs)
	defer c.Close()

	session, err := c.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	// Wire I/O without requesting a PTY.
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Run(command); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitStatus())
		}
		return fmt.Errorf("run remote command: %w", err)
	}
	return nil
}
