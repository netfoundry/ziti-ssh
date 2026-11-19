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
	"net"
	"testing"
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
