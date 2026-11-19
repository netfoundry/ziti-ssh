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
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/netfoundry/ziti-ssh/ca"
	"github.com/netfoundry/ziti-ssh/internal/ratelimit"
)

// zitiLikeConn mimics an SDK edge connection: SourceIdentifier() is the
// client-supplied CallerId header, GetDialerIdentityName() is the
// router-verified dialer identity.
type zitiLikeConn struct {
	net.Conn
	callerID   string
	dialerName string
}

func (c *zitiLikeConn) SourceIdentifier() string      { return c.callerID }
func (c *zitiLikeConn) GetDialerIdentityName() string { return c.dialerName }

func TestCallerIdentity_TrustsOnlyRouterVerifiedIdentity(t *testing.T) {
	cases := []struct {
		name       string
		callerID   string
		dialerName string
		want       string
	}{
		{"mismatched caller id, no router identity", "root", "", ""},
		{"mismatched caller id, router identity present", "root", "alice", "alice"},
		{"matching values", "alice", "alice", "alice"},
		{"router identity only", "", "alice", "alice"},
		{"neither", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := callerIdentity(&zitiLikeConn{callerID: tc.callerID, dialerName: tc.dialerName})
			if got != tc.want {
				t.Fatalf("callerIdentity() = %q, want %q", got, tc.want)
			}
		})
	}
}

// sourceOnlyConn exposes only the client-supplied CallerId, which was
// previously trusted and must now be ignored.
type sourceOnlyConn struct {
	net.Conn
	callerID string
}

func (c *sourceOnlyConn) SourceIdentifier() string { return c.callerID }

func TestCallerIdentity_SourceIdentifierOnlyConnIsRejected(t *testing.T) {
	if got := callerIdentity(&sourceOnlyConn{callerID: "root"}); got != "" {
		t.Fatalf("callerIdentity() = %q, want empty", got)
	}
}

func testCASigner(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, ca.PublicKeyBytes(signer.PublicKey())
}

// serve runs handleConn on the server end of a pipe whose caller identity is
// "alice", and returns the client end.
func serve(t *testing.T, signer ssh.Signer, caPub []byte, limiter *ratelimit.Map) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go handleConn(&zitiLikeConn{Conn: server, dialerName: "alice"}, signer, caPub, "ziggy", "shared",
		5*time.Minute, ca.DefaultSourceAddress, []string{"permit-pty"}, limiter)
	t.Cleanup(func() { client.Close() })
	return client
}

func readLine(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && line == "" {
		t.Fatalf("no reply from CA within 2s: %v", err)
	}
	return strings.TrimSpace(line)
}

func TestHandleConn_RateLimitCheckedBeforeReading(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	limiter := ratelimit.New(1.0/3600, 1, time.Hour, stop) // one request, then limited
	signer, caPub := testCASigner(t)

	// First request: a CA public-key request. It must be served — and count
	// against the identity's rate limit.
	c1 := serve(t, signer, caPub, limiter)
	if _, err := c1.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	if got := readLine(t, c1); got != strings.TrimSpace(string(caPub)) {
		t.Fatalf("CA public key request: got %q", got)
	}

	// Second request: the client sends nothing. The CA must reply with the
	// rate-limit error without waiting to read a request line.
	c2 := serve(t, signer, caPub, limiter)
	if got := readLine(t, c2); got != "error: rate limit exceeded" {
		t.Fatalf("want rate-limit error before any request is read, got %q", got)
	}
}

func TestDispatch_ConnectionCap(t *testing.T) {
	slots := make(chan struct{}, 1)
	var wg sync.WaitGroup
	release := make(chan struct{})
	var mu sync.Mutex
	handled := map[string]bool{}
	handler := func(name string) func(net.Conn) {
		return func(c net.Conn) {
			mu.Lock()
			handled[name] = true
			mu.Unlock()
			<-release
			c.Close()
		}
	}

	aClient, aServer := net.Pipe()
	defer aClient.Close()
	if !dispatch(aServer, slots, &wg, handler("a")) {
		t.Fatal("first connection rejected with a free slot")
	}

	bClient, bServer := net.Pipe()
	defer bClient.Close()
	if dispatch(bServer, slots, &wg, handler("b")) {
		t.Fatal("connection accepted beyond the cap")
	}
	_ = bClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bClient.Read(make([]byte, 1)); err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("over-cap connection not closed: %v", err)
	}

	close(release) // finish "a"; its slot must be returned
	wg.Wait()

	cClient, cServer := net.Pipe()
	defer cClient.Close()
	if !dispatch(cServer, slots, &wg, handler("c")) {
		t.Fatal("slot not released after the handler returned")
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if handled["b"] {
		t.Error("handler ran for the rejected connection")
	}
	if !handled["a"] || !handled["c"] {
		t.Errorf("handlers not run for admitted connections: %v", handled)
	}
}
