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

// Package ca provides SSH certificate authority operations: loading Ed25519 CA
// keys and signing short-lived SSH user certificates bound to Ziti identities.
package ca

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// LoadKey reads an Ed25519 private key from path and returns an ssh.Signer
// and the corresponding ssh.PublicKey. The key must be stored in PEM format
// (as produced by ssh-keygen -t ed25519).
func LoadKey(path string) (ssh.Signer, ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key %q: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key %q: %w", path, err)
	}

	return signer, signer.PublicKey(), nil
}

// SignCert signs a short-lived SSH user certificate for the given public key.
// identity is the Ziti identity name of the caller (embedded in the Key ID for
// audit purposes). principal is the Linux username the cert grants access to.
// ttl controls validity duration — pass 8*time.Hour for standard production use.
//
// The returned bytes are in authorized_keys format, ready to write to a
// ~/.ssh/<key>-cert.pub file.
func SignCert(signer ssh.Signer, pubKey ssh.PublicKey, identity, principal string, ttl time.Duration) ([]byte, error) {
	if identity == "" {
		return nil, fmt.Errorf("identity must not be empty")
	}
	if principal == "" {
		return nil, fmt.Errorf("principal must not be empty")
	}

	now := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pubKey,
		KeyId:           "ziti:" + identity,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-port-forwarding":  "",
				"permit-agent-forwarding": "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return ssh.MarshalAuthorizedKey(cert), nil
}

// PublicKeyBytes marshals pub to authorized_keys format.
func PublicKeyBytes(pub ssh.PublicKey) []byte {
	return ssh.MarshalAuthorizedKey(pub)
}

// DeriveUsername maps a Ziti identity name to a valid Linux username.
//
// Rules applied in order:
//  1. Lowercase the entire string.
//  2. Replace any character outside [a-z0-9_-] with '_'.
//  3. If the result starts with a digit, prefix with 'z'.
//  4. Truncate to 32 characters.
//
// The result is guaranteed to be non-empty as long as identity is non-empty,
// because every character is either kept or replaced with '_'.
func DeriveUsername(identity string) string {
	// Step 1: lowercase.
	s := strings.Map(unicode.ToLower, identity)

	// Step 2: replace characters outside [a-z0-9_-] with '_'.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	result := b.String()

	// Step 3: prefix with 'z' if first character is a digit.
	if len(result) > 0 && result[0] >= '0' && result[0] <= '9' {
		result = "z" + result
	}

	// Step 4: truncate to 32 characters.
	if len(result) > 32 {
		result = result[:32]
	}

	return result
}
