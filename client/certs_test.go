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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signCert(t *testing.T, ca ssh.Signer, key ssh.PublicKey, certType uint32, lifetime time.Duration) *ssh.Certificate {
	t.Helper()
	now := time.Now()
	c := &ssh.Certificate{
		Key:             key,
		CertType:        certType,
		KeyId:           "ziti:test",
		ValidPrincipals: []string{"ziggy"},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(lifetime).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func authLine(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }

func TestValidateSignedCert(t *testing.T) {
	ca, user, other := newKey(t), newKey(t), newKey(t)
	ourPub := authLine(user.PublicKey())

	good := authLine(signCert(t, ca, user.PublicKey(), ssh.UserCert, 5*time.Minute))
	if out, err := ValidateSignedCert(good, ourPub); err != nil || !strings.HasPrefix(string(out), "ssh-ed25519-cert-v01@openssh.com ") {
		t.Fatalf("valid cert rejected: out=%q err=%v", out, err)
	}

	cases := []struct {
		name string
		line string
	}{
		{"empty", ""},
		{"junk", "not a certificate"},
		{"plain public key", ourPub},
		{"certificate for another key", authLine(signCert(t, ca, other.PublicKey(), ssh.UserCert, 5*time.Minute))},
		{"host certificate", authLine(signCert(t, ca, user.PublicKey(), ssh.HostCert, 5*time.Minute))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateSignedCert(tc.line, ourPub); err == nil {
				t.Fatal("accepted, want error")
			}
		})
	}

	_, err := ValidateSignedCert("error: rate limit exceeded", ourPub)
	var rej *CARejectedError
	if !errors.As(err, &rej) || rej.Reason != "rate limit exceeded" {
		t.Fatalf("error reply: got %v, want CARejectedError(rate limit exceeded)", err)
	}
}

func TestReadCAResponse(t *testing.T) {
	if got, err := ReadCAResponse(strings.NewReader("ssh-ed25519-cert AAAA\nextra")); err != nil || got != "ssh-ed25519-cert AAAA" {
		t.Errorf("newline-terminated: got %q, %v", got, err)
	}
	if got, err := ReadCAResponse(strings.NewReader("error: rate limit exceeded")); err != nil || got != "error: rate limit exceeded" {
		t.Errorf("EOF without newline: got %q, %v", got, err)
	}
	if _, err := ReadCAResponse(strings.NewReader("")); err == nil {
		t.Error("empty response accepted")
	}
	if _, err := ReadCAResponse(strings.NewReader(strings.Repeat("A", MaxCAResponseBytes+10) + "\n")); err == nil {
		t.Error("oversized response accepted")
	}
}

func TestCertNeedsRefreshAt(t *testing.T) {
	ca, user := newKey(t), newKey(t)
	now := time.Now()

	fiveMin := signCert(t, ca, user.PublicKey(), ssh.UserCert, 5*time.Minute)
	if got := certRefreshThreshold(fiveMin); got != time.Minute {
		t.Errorf("5m cert threshold = %v, want 1m", got)
	}
	// Regression: a fresh 5-minute cert must not be refreshed immediately.
	if certNeedsRefreshAt(fiveMin, now) {
		t.Error("fresh 5-minute certificate needs refresh (re-sign on every call)")
	}
	if certNeedsRefreshAt(fiveMin, now.Add(3*time.Minute)) {
		t.Error("5-minute certificate with 2m left needs refresh")
	}
	if !certNeedsRefreshAt(fiveMin, now.Add(4*time.Minute+30*time.Second)) {
		t.Error("5-minute certificate with 30s left does not need refresh")
	}
	if !certNeedsRefreshAt(fiveMin, now.Add(6*time.Minute)) {
		t.Error("expired certificate does not need refresh")
	}

	eightHour := signCert(t, ca, user.PublicKey(), ssh.UserCert, 8*time.Hour)
	if got := certRefreshThreshold(eightHour); got != 5*time.Minute {
		t.Errorf("8h cert threshold = %v, want 5m (unchanged behaviour)", got)
	}

	oneMin := signCert(t, ca, user.PublicKey(), ssh.UserCert, time.Minute)
	if got := certRefreshThreshold(oneMin); got != 30*time.Second {
		t.Errorf("1m cert threshold = %v, want 30s floor", got)
	}

	forever := &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}
	if certNeedsRefreshAt(forever, now) {
		t.Error("non-expiring certificate needs refresh")
	}
}
