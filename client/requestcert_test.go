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
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// fakeCAConn is a CA connection whose write may fail while a reply is waiting.
type fakeCAConn struct {
	writeErr error
	reply    io.Reader
	written  bytes.Buffer
}

func (c *fakeCAConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.written.Write(p)
}
func (c *fakeCAConn) Read(p []byte) (int, error) { return c.reply.Read(p) }

func TestRequestCert(t *testing.T) {
	writeErr := errors.New("connection closed for writes")

	t.Run("normal", func(t *testing.T) {
		c := &fakeCAConn{reply: strings.NewReader("ssh-ed25519-cert-v01@openssh.com AAAA\n")}
		line, err := RequestCert(c, "ssh-ed25519 AAAA key")
		if err != nil || line != "ssh-ed25519-cert-v01@openssh.com AAAA" {
			t.Fatalf("line %q, err %v", line, err)
		}
		if c.written.String() != "ssh-ed25519 AAAA key\n" {
			t.Errorf("sent %q", c.written.String())
		}
	})
	t.Run("write fails, refusal readable", func(t *testing.T) {
		c := &fakeCAConn{writeErr: writeErr, reply: strings.NewReader("error: rate limit exceeded\n")}
		_, err := RequestCert(c, "k")
		var rej *CARejectedError
		if !errors.As(err, &rej) || rej.Reason != "rate limit exceeded" {
			t.Fatalf("err = %v, want CARejectedError(rate limit exceeded)", err)
		}
	})
	t.Run("write fails, nothing readable", func(t *testing.T) {
		c := &fakeCAConn{writeErr: writeErr, reply: strings.NewReader("")}
		_, err := RequestCert(c, "k")
		if !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "send public key to CA") {
			t.Fatalf("err = %v, want the write error", err)
		}
	})
	t.Run("write fails, certificate-like reply is not trusted", func(t *testing.T) {
		c := &fakeCAConn{writeErr: writeErr, reply: strings.NewReader("ssh-ed25519-cert-v01@openssh.com AAAA\n")}
		if _, err := RequestCert(c, "k"); !errors.Is(err, writeErr) {
			t.Fatalf("err = %v, want the write error", err)
		}
	})
}

func TestHandshakeErrorHint(t *testing.T) {
	// x/crypto wraps the cause with %w ("ssh: handshake failed: %w").
	for _, e := range []error{
		fmt.Errorf("ssh: handshake failed: %w", io.EOF),
		fmt.Errorf("ssh: handshake failed: %w", errors.New("connection closed for writes")),
	} {
		if got := handshakeError("h", e).Error(); !strings.Contains(got, "ziti-ssh-host may have refused") {
			t.Errorf("%v: no hint in %q", e, got)
		}
	}
	got := handshakeError("h", errors.New("ssh: handshake failed: ssh: unable to authenticate")).Error()
	if strings.Contains(got, "may have refused") {
		t.Errorf("hint added to an authentication failure: %q", got)
	}
}
