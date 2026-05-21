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

// Package client provides SSH session helpers for the ziti-ssh CLI.
//
// Exported functions cover the lifecycle of a certificate-backed SSH session
// over a pre-dialed net.Conn:
//
//   - NewCertSigner      — loads a private key and, if a matching -cert.pub file
//     exists, wraps it in an ssh.CertSigner so the certificate
//     is presented during authentication.
//
//   - CertNeedsRefresh   — returns true when the cert file is missing or will
//     expire within 5 minutes.
//
//   - NewSSHClient       — performs the SSH handshake over a pre-dialed net.Conn
//     and returns an *ssh.Client ready for sessions or forwards.
//
//   - RunSession         — runs a full interactive SSH session with PTY over a
//     net.Conn that has already been dialled (e.g. via ziti.Dial).
//
//   - RunCommand         — runs a single non-interactive remote command over a
//     net.Conn that has already been dialled. No PTY is allocated.
//     The remote exit code is propagated via os.Exit.
//
//   - ForwardAgent       — sets up SSH agent forwarding on an already-opened
//     *ssh.Client and *ssh.Session. Non-fatal if SSH_AUTH_SOCK
//     is unset or the agent is unreachable.
//
//   - RunLocalForward    — listens locally and forwards each connection to a
//     remote host:port via a direct-tcpip channel (-L).
//
//   - RunRemoteForward   — asks sshd to listen remotely and forwards each
//     incoming connection to a local host:port (-R).
//
//   - RunDynamicProxy    — listens locally as a SOCKS5 proxy and tunnels each
//     connection through a direct-tcpip channel (-D).
package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
// either absent or will expire within 5 minutes of the time this function is
// called. It returns false if the file is present and has more than 5 minutes
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
	return time.Until(expiry) < 5*time.Minute
}

// RunSession opens an interactive SSH shell session over conn.
//
// conn must already be a connected net.Conn (e.g. returned by ziti.Dial).
// user is the remote username; host is used only as the hostname passed to
// ssh.NewClientConn (OpenSSH convention — it does not perform DNS resolution
// here). signer provides the public-key / certificate auth credential.
//
// When forwardAgent is true, RunSession connects to the local SSH agent via
// SSH_AUTH_SOCK and enables agent forwarding on the session so that remote
// processes can use local agent keys (e.g. for onward SSH hops). If
// SSH_AUTH_SOCK is not set or the agent cannot be reached, a warning is logged
// and the session continues without agent forwarding — it is non-fatal.
//
// The terminal is placed in raw mode for the duration of the session and
// restored on return (even on error).
//
// Host key verification is intentionally skipped. The connection arrives over
// a Ziti overlay that enforces mutual TLS using the controller's PKI — the
// host's Ziti identity is cryptographically proven before any SSH bytes are
// exchanged. A traditional known-hosts check would be redundant and weaker
// than the guarantee Ziti already provides.
func RunSession(conn net.Conn, user, host string, signer ssh.Signer, forwardAgent bool) error {
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

	// Wire up terminal I/O.
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if forwardAgent {
		if err := ForwardAgent(c, session); err != nil {
			slog.Warn("agent forwarding unavailable", "err", err)
		}
	}

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

	if err := session.Wait(); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			_ = term.Restore(stdinFd, oldState)
			os.Exit(exitErr.ExitStatus())
		}
		return err
	}
	return nil
}

// ForwardAgent sets up SSH agent forwarding on an already-opened session.
//
// It connects to the local SSH agent via SSH_AUTH_SOCK, registers the agent on
// sshClient so the remote can open agent channels back to the local process,
// then sends the auth-agent-req@openssh.com channel request on session so that
// the remote shell has access to the local agent.
//
// If SSH_AUTH_SOCK is not set or the agent cannot be reached, a descriptive
// error is returned. The caller should treat this as a warning and continue
// the session without agent forwarding rather than aborting.
//
// The agent connection is closed automatically when sshClient is closed —
// no separate cleanup is required by the caller.
func ForwardAgent(sshClient *ssh.Client, session *ssh.Session) error {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return fmt.Errorf("SSH_AUTH_SOCK is not set; start an SSH agent (e.g. eval \"$(ssh-agent -s)\") and add your key with ssh-add")
	}

	agentConn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("connect to SSH agent at %q: %w", sockPath, err)
	}
	// agentConn is adopted by agent.NewClient and will be closed when
	// sshClient.Close() tears down the underlying transport — the agent package
	// does not close it itself, but the goroutine launched by ForwardToAgent
	// terminates when the client connection is gone, and the OS reclaims the
	// unix socket FD at that point. We explicitly close it as a belt-and-
	// suspenders measure when the sshClient goes away by registering a cleanup
	// on the client's Done channel in a background goroutine.
	agentClient := agent.NewClient(agentConn)

	// ForwardToAgent registers a handler on sshClient for incoming
	// "auth-agent@openssh.com" channels opened by the remote host so it can
	// proxy agent requests back to agentClient.
	if err := agent.ForwardToAgent(sshClient, agentClient); err != nil {
		_ = agentConn.Close()
		return fmt.Errorf("register agent on SSH client: %w", err)
	}

	// Close agentConn when the SSH client transport closes.
	go func() {
		sshClient.Wait() //nolint:errcheck // just waiting for close
		_ = agentConn.Close()
	}()

	// RequestAgentForwarding sends the auth-agent-req@openssh.com request on
	// the session so that sshd enables agent forwarding for this session.
	if err := agent.RequestAgentForwarding(session); err != nil {
		return fmt.Errorf("request agent forwarding on session: %w", err)
	}

	slog.Debug("SSH agent forwarding enabled", "sock", sockPath)
	return nil
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

// NewSSHClient performs the SSH handshake over conn and returns an *ssh.Client.
//
// Unlike RunSession and RunCommand, this function does not open a session —
// it returns the raw *ssh.Client so the caller can open sessions or set up
// port forwards independently. The caller is responsible for calling
// client.Close() when done.
//
// Host key verification is intentionally skipped (see RunSession for rationale).
func NewSSHClient(conn net.Conn, user, host string, signer ssh.Signer) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH handshake with %q: %w", host, err)
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// ---------------------------------------------------------------------------
// Port forwarding — local (-L), remote (-R), dynamic SOCKS5 (-D)
// ---------------------------------------------------------------------------

// LocalForwardSpec describes a single -L forward:
//
//	[bind:]localport:remotehost:remoteport
//
// If Bind is empty, the listener is bound to 127.0.0.1.
type LocalForwardSpec struct {
	Bind       string // local bind address (default: 127.0.0.1)
	LocalPort  string // local port to listen on
	RemoteHost string // remote host sshd forwards to
	RemotePort string // remote port sshd forwards to
}

// RemoteForwardSpec describes a single -R forward:
//
//	[bind:]remoteport:localhost:localport
//
// If Bind is empty, sshd binds to all interfaces (RFC 4254 §7.1).
type RemoteForwardSpec struct {
	Bind       string // remote bind address (empty = sshd default)
	RemotePort string // port sshd listens on
	LocalHost  string // local host to forward to
	LocalPort  string // local port to forward to
}

// DynamicForwardSpec describes a single -D SOCKS5 proxy listener:
//
//	[bind:]port
//
// If Bind is empty, the listener is bound to 127.0.0.1.
type DynamicForwardSpec struct {
	Bind      string // local bind address (default: 127.0.0.1)
	LocalPort string // local port to listen on
}

// RunLocalForward binds a local TCP listener and forwards each accepted
// connection to remoteHost:remotePort through the SSH client using a
// direct-tcpip channel. It runs until ctx is cancelled.
//
// This implements the -L flag behaviour of ssh(1).
func RunLocalForward(ctx context.Context, sshClient *ssh.Client, spec LocalForwardSpec) error {
	bind := spec.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(bind, spec.LocalPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("local forward: listen on %s: %w", listenAddr, err)
	}

	slog.Info("local forward active", "listen", listenAddr,
		"remote", net.JoinHostPort(spec.RemoteHost, spec.RemotePort))

	// Close the listener when the context is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // context cancelled — clean exit
			}
			return fmt.Errorf("local forward: accept: %w", err)
		}
		go handleLocalForwardConn(ctx, sshClient, local, spec.RemoteHost, spec.RemotePort)
	}
}

func handleLocalForwardConn(ctx context.Context, sshClient *ssh.Client, local net.Conn, remoteHost, remotePort string) {
	defer local.Close()

	remote, err := sshClient.DialContext(ctx, "tcp", net.JoinHostPort(remoteHost, remotePort))
	if err != nil {
		slog.Warn("local forward: dial remote failed",
			"remote", net.JoinHostPort(remoteHost, remotePort), "err", err)
		return
	}
	defer remote.Close()

	slog.Debug("local forward: connection established",
		"local", local.RemoteAddr(), "remote", net.JoinHostPort(remoteHost, remotePort))

	biCopy(ctx, local, remote)
}

// RunRemoteForward asks the SSH server to listen on a remote port and
// forwards each incoming connection to localHost:localPort on the client.
// It runs until ctx is cancelled.
//
// This implements the -R flag behaviour of ssh(1).
func RunRemoteForward(ctx context.Context, sshClient *ssh.Client, spec RemoteForwardSpec) error {
	remoteAddr := net.JoinHostPort(spec.Bind, spec.RemotePort)
	ln, err := sshClient.Listen("tcp", remoteAddr)
	if err != nil {
		return fmt.Errorf("remote forward: request remote listen on %s: %w", remoteAddr, err)
	}

	slog.Info("remote forward active", "remote_listen", remoteAddr,
		"local", net.JoinHostPort(spec.LocalHost, spec.LocalPort))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		remote, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("remote forward: accept: %w", err)
		}
		go handleRemoteForwardConn(ctx, remote, spec.LocalHost, spec.LocalPort)
	}
}

func handleRemoteForwardConn(ctx context.Context, remote net.Conn, localHost, localPort string) {
	defer remote.Close()

	local, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(localHost, localPort))
	if err != nil {
		slog.Warn("remote forward: dial local failed",
			"local", net.JoinHostPort(localHost, localPort), "err", err)
		return
	}
	defer local.Close()

	slog.Debug("remote forward: connection established",
		"remote", remote.RemoteAddr(), "local", net.JoinHostPort(localHost, localPort))

	biCopy(ctx, remote, local)
}

// RunDynamicProxy listens locally as a minimal SOCKS5 proxy (RFC 1928).
// For each CONNECT request it opens a direct-tcpip channel through the SSH
// client to the destination the SOCKS5 client requested. Only the CONNECT
// command with no-authentication is supported — sufficient for most use cases.
// It runs until ctx is cancelled.
//
// This implements the -D flag behaviour of ssh(1).
func RunDynamicProxy(ctx context.Context, sshClient *ssh.Client, spec DynamicForwardSpec) error {
	bind := spec.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(bind, spec.LocalPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("dynamic proxy: listen on %s: %w", listenAddr, err)
	}

	slog.Info("dynamic SOCKS5 proxy active", "listen", listenAddr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("dynamic proxy: accept: %w", err)
		}
		go handleSocks5Conn(ctx, sshClient, conn)
	}
}

// handleSocks5Conn performs the SOCKS5 handshake (RFC 1928) and then proxies
// the connection through sshClient. Only CONNECT (0x01) with ATYP IPv4 (0x01),
// domain name (0x03), and IPv6 (0x04) are supported.
func handleSocks5Conn(ctx context.Context, sshClient *ssh.Client, conn net.Conn) {
	defer conn.Close()

	// --- Greeting ---
	// Read VER + NMETHODS + METHODS.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		slog.Debug("socks5: read greeting failed", "err", err)
		return
	}
	if header[0] != 0x05 {
		slog.Debug("socks5: unsupported version", "ver", header[0])
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		slog.Debug("socks5: read methods failed", "err", err)
		return
	}
	// Respond: VER=5, METHOD=0 (no auth).
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		slog.Debug("socks5: write auth response failed", "err", err)
		return
	}

	// --- Request ---
	// VER CMD RSV ATYP
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		slog.Debug("socks5: read request header failed", "err", err)
		return
	}
	if reqHeader[0] != 0x05 {
		slog.Debug("socks5: bad request version", "ver", reqHeader[0])
		return
	}
	if reqHeader[1] != 0x01 {
		// Only CONNECT supported.
		slog.Debug("socks5: unsupported command", "cmd", reqHeader[1])
		writeSocks5Reply(conn, 0x07, nil) // command not supported
		return
	}

	var destHost string
	switch reqHeader[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			slog.Debug("socks5: read IPv4 addr failed", "err", err)
			return
		}
		destHost = net.IP(addr).String()

	case 0x03: // domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			slog.Debug("socks5: read domain len failed", "err", err)
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			slog.Debug("socks5: read domain failed", "err", err)
			return
		}
		destHost = string(domain)

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			slog.Debug("socks5: read IPv6 addr failed", "err", err)
			return
		}
		destHost = "[" + net.IP(addr).String() + "]"

	default:
		slog.Debug("socks5: unsupported address type", "atyp", reqHeader[3])
		writeSocks5Reply(conn, 0x08, nil) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		slog.Debug("socks5: read port failed", "err", err)
		return
	}
	destPort := int(binary.BigEndian.Uint16(portBuf))
	destAddr := fmt.Sprintf("%s:%d", destHost, destPort)

	// Dial through the SSH tunnel.
	remote, err := sshClient.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		slog.Warn("socks5: dial remote failed", "dest", destAddr, "err", err)
		writeSocks5Reply(conn, 0x05, nil) // connection refused
		return
	}
	defer remote.Close()

	// Success reply — BND.ADDR and BND.PORT are zeros (not meaningful here).
	writeSocks5Reply(conn, 0x00, nil)

	slog.Debug("socks5: connection established", "dest", destAddr)
	biCopy(ctx, conn, remote)
}

// writeSocks5Reply writes a SOCKS5 reply with the given status byte.
// bndAddr may be nil; in that case zeros are written for BND.ADDR/BND.PORT.
func writeSocks5Reply(conn net.Conn, status byte, _ net.Addr) {
	// VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
	reply := []byte{0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _ = conn.Write(reply)
}

// biCopy copies data bidirectionally between a and b until either side closes
// or ctx is cancelled. It is used for all forwarding paths.
func biCopy(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		if _, err := io.Copy(dst, src); err != nil && ctx.Err() == nil {
			slog.Debug("forward: copy error", "err", err)
		}
		// Half-close to unblock the other direction.
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	select {
	case <-done:
	case <-ctx.Done():
	}
}
