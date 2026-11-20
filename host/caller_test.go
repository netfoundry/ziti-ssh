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

package host

import (
	"net"
	"testing"
	"time"
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

func TestCallerName_TrustsOnlyRouterVerifiedIdentity(t *testing.T) {
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
			got := callerName(&zitiLikeConn{callerID: tc.callerID, dialerName: tc.dialerName})
			if got != tc.want {
				t.Fatalf("callerName() = %q, want %q", got, tc.want)
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

func TestCallerName_SourceIdentifierOnlyConnIsRejected(t *testing.T) {
	if got := callerName(&sourceOnlyConn{callerID: "root"}); got != "" {
		t.Fatalf("callerName() = %q, want empty", got)
	}
}

// targetListener starts a TCP listener standing in for sshd and returns its
// address and a channel that receives each accepted connection.
func targetListener(t *testing.T) (string, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return ln.Addr().String(), accepted
}

func TestProxyConn_HooksWithoutRouterIdentity_FailsClosed(t *testing.T) {
	target, accepted := targetListener(t)

	client, server := net.Pipe()
	defer client.Close()

	connectCalled := false
	hooks := &ProxyHooks{
		OnConnect:    func(string) error { connectCalled = true; return nil },
		OnDisconnect: func(string) {},
	}

	// Client-supplied CallerId only, no router-verified identity. Run in a goroutine so a
	// regression (proxying instead of rejecting) fails rather than hangs.
	done := make(chan struct{})
	go func() {
		proxyConn(&zitiLikeConn{Conn: server, callerID: "root"}, target, hooks)
		close(done)
	}()

	select {
	case c := <-accepted:
		c.Close()
		client.Close()
		<-done
		t.Fatal("connection was proxied to the target without a router-verified identity")
	case <-done:
	case <-time.After(2 * time.Second):
		client.Close()
		<-done
		t.Fatal("proxyConn did not return promptly for a connection without a router-verified identity")
	}
	if connectCalled {
		t.Fatal("OnConnect was called for a connection without a router-verified identity")
	}
}

func TestProxyConn_HooksReceiveRouterIdentityNotCallerID(t *testing.T) {
	target, accepted := targetListener(t)

	client, server := net.Pipe()

	var gotIdentity string
	hooks := &ProxyHooks{
		OnConnect:    func(id string) error { gotIdentity = id; return nil },
		OnDisconnect: func(string) {},
	}

	done := make(chan struct{})
	go func() {
		proxyConn(&zitiLikeConn{Conn: server, callerID: "root", dialerName: "alice"}, target, hooks)
		close(done)
	}()

	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("connection with a router-verified identity was not proxied")
	}
	client.Close()
	<-done

	if gotIdentity != "alice" {
		t.Fatalf("OnConnect received %q, want router-verified %q", gotIdentity, "alice")
	}
}

func TestProxyConn_NoHooks_SharedModeStillProxies(t *testing.T) {
	target, accepted := targetListener(t)

	client, server := net.Pipe()

	done := make(chan struct{})
	go func() {
		// Shared mode: no hooks, no identity needed on the host side.
		proxyConn(&zitiLikeConn{Conn: server}, target, nil)
		close(done)
	}()

	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("shared-mode connection was not proxied")
	}
	client.Close()
	<-done
}
