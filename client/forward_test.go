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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// echoServer accepts connections on network/addr and echoes everything back.
func echoServer(t *testing.T, network, addr string) string {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func pipeChannel(ch ssh.Channel, c net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(ch, c); _ = ch.CloseWrite() }()
	go func() { defer wg.Done(); _, _ = io.Copy(c, ch) }()
	wg.Wait()
	ch.Close()
	c.Close()
}

// testSSHClient starts an in-process SSH server that implements direct-tcpip
// (for -L / -D) and tcpip-forward (for -R), and returns a client for it.
func testSSHClient(t *testing.T) *ssh.Client {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(nc, cfg)
		}
	}()

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // in-process test server
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func serveSSH(nc net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go func() {
		for req := range reqs {
			if req.Type != "tcpip-forward" {
				_ = req.Reply(false, nil)
				continue
			}
			var fwd struct {
				Addr string
				Port uint32
			}
			if ssh.Unmarshal(req.Payload, &fwd) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			rl, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(fwd.Port))))
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go func() {
				defer rl.Close()
				for {
					c, err := rl.Accept()
					if err != nil {
						return
					}
					payload := ssh.Marshal(struct {
						Addr     string
						Port     uint32
						OrigAddr string
						OrigPort uint32
					}{fwd.Addr, fwd.Port, "127.0.0.1", uint32(c.RemoteAddr().(*net.TCPAddr).Port)})
					ch, chReqs, err := sconn.OpenChannel("forwarded-tcpip", payload)
					if err != nil {
						c.Close()
						continue
					}
					go ssh.DiscardRequests(chReqs)
					go pipeChannel(ch, c)
				}
			}()
			go func() { _ = sconn.Wait(); rl.Close() }()
		}
	}()
	for nch := range chans {
		if nch.ChannelType() != "direct-tcpip" {
			_ = nch.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		var d struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if ssh.Unmarshal(nch.ExtraData(), &d) != nil {
			_ = nch.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		c, err := net.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))))
		if err != nil {
			_ = nch.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			c.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go pipeChannel(ch, c)
	}
}

// dialRetry dials addr until it is accepted (the forward starts listening
// asynchronously).
func dialRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func assertEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestRunLocalForward(t *testing.T) {
	client := testSSHClient(t)
	echoHost, echoPort, _ := net.SplitHostPort(echoServer(t, "tcp", "127.0.0.1:0"))
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunLocalForward(ctx, client, LocalForwardSpec{Bind: "127.0.0.1", LocalPort: port, RemoteHost: echoHost, RemotePort: echoPort})
	}()
	c := dialRetry(t, net.JoinHostPort("127.0.0.1", port))
	assertEcho(t, c, "hello through -L")
	c.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunLocalForward after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunLocalForward did not stop on cancel")
	}
}

func TestRunRemoteForward(t *testing.T) {
	client := testSSHClient(t)
	echoHost, echoPort, _ := net.SplitHostPort(echoServer(t, "tcp", "127.0.0.1:0"))
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = RunRemoteForward(ctx, client, RemoteForwardSpec{Bind: "127.0.0.1", RemotePort: port, LocalHost: echoHost, LocalPort: echoPort})
	}()
	// The test server listens on the requested port on the "remote" side as
	// soon as it accepts the request; the client registers the forward only
	// after the reply, so an early connection can be rejected. Retry until a
	// round trip succeeds.
	addr := net.JoinHostPort("127.0.0.1", port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c := dialRetry(t, addr)
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		msg := "hello through -R"
		_, werr := c.Write([]byte(msg))
		buf := make([]byte, len(msg))
		_, rerr := io.ReadFull(c, buf)
		c.Close()
		if werr == nil && rerr == nil && string(buf) == msg {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no echo through -R: write %v, read %v, got %q", werr, rerr, buf)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// socks5 opens a connection to the proxy and performs the greeting with the
// given methods, returning the connection and the server's method choice.
func socks5(t *testing.T, proxy string, methods ...byte) (net.Conn, []byte) {
	t.Helper()
	c := dialRetry(t, proxy)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	return c, reply
}

func socks5Connect(t *testing.T, c net.Conn, cmd, atyp byte, addr []byte, port uint16) byte {
	t.Helper()
	req := append([]byte{0x05, cmd, 0x00, atyp}, addr...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return reply[1]
}

func TestRunDynamicProxy_SOCKS5(t *testing.T) {
	client := testSSHClient(t)
	_, echoPortStr, _ := net.SplitHostPort(echoServer(t, "tcp", "127.0.0.1:0"))
	echoPort, _ := strconv.Atoi(echoPortStr)
	port := freePort(t)
	proxy := net.JoinHostPort("127.0.0.1", port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = RunDynamicProxy(ctx, client, DynamicForwardSpec{Bind: "127.0.0.1", LocalPort: port}) }()

	t.Run("IPv4", func(t *testing.T) {
		c, m := socks5(t, proxy, 0x00)
		defer c.Close()
		if !bytes.Equal(m, []byte{0x05, 0x00}) {
			t.Fatalf("method reply %v", m)
		}
		if st := socks5Connect(t, c, 0x01, 0x01, net.ParseIP("127.0.0.1").To4(), uint16(echoPort)); st != 0x00 {
			t.Fatalf("status %#x", st)
		}
		assertEcho(t, c, "ipv4")
	})
	t.Run("DomainName", func(t *testing.T) {
		c, _ := socks5(t, proxy, 0x02, 0x00)
		defer c.Close()
		name := []byte("localhost")
		if st := socks5Connect(t, c, 0x01, 0x03, append([]byte{byte(len(name))}, name...), uint16(echoPort)); st != 0x00 {
			t.Skipf("localhost did not resolve to the IPv4 echo server (status %#x)", st)
		}
		assertEcho(t, c, "domain")
	})
	t.Run("IPv6", func(t *testing.T) {
		_, p6, _ := net.SplitHostPort(echoServer(t, "tcp6", "[::1]:0"))
		port6, _ := strconv.Atoi(p6)
		c, _ := socks5(t, proxy, 0x00)
		defer c.Close()
		if st := socks5Connect(t, c, 0x01, 0x04, net.ParseIP("::1").To16(), uint16(port6)); st != 0x00 {
			t.Fatalf("status %#x", st)
		}
		assertEcho(t, c, "ipv6")
	})
	t.Run("UnsupportedCommand", func(t *testing.T) {
		c, _ := socks5(t, proxy, 0x00)
		defer c.Close()
		if st := socks5Connect(t, c, 0x02 /* BIND */, 0x01, net.ParseIP("127.0.0.1").To4(), uint16(echoPort)); st != 0x07 {
			t.Fatalf("BIND status %#x, want 0x07", st)
		}
	})
	t.Run("UnsupportedAddressType", func(t *testing.T) {
		c, _ := socks5(t, proxy, 0x00)
		defer c.Close()
		if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x09}); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0x08 {
			t.Fatalf("reply %v, %v; want status 0x08", reply, err)
		}
	})
	t.Run("RefusesWithoutNoAuthMethod", func(t *testing.T) {
		c, m := socks5(t, proxy, 0x02) // username/password only
		defer c.Close()
		if !bytes.Equal(m, []byte{0x05, 0xFF}) {
			t.Fatalf("method reply %v, want [5 255]", m)
		}
	})
	t.Run("RefusesSOCKS4", func(t *testing.T) {
		c := dialRetry(t, proxy)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0})
		// Closed without a reply (EOF, or a reset because the request was
		// left unread).
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("SOCKS4 not refused: read %d bytes, %v", n, err)
		}
	})
	t.Run("ConnectionRefusedStatus", func(t *testing.T) {
		c, _ := socks5(t, proxy, 0x00)
		defer c.Close()
		closed, _ := strconv.Atoi(freePort(t))
		if st := socks5Connect(t, c, 0x01, 0x01, net.ParseIP("127.0.0.1").To4(), uint16(closed)); st != 0x05 {
			t.Fatalf("status %#x, want 0x05", st)
		}
	})
}
