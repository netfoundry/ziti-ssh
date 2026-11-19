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

// Package ca provides SSH certificate authority operations: loading the CA key
// (the Ziti controller's intermediate CA private key — RSA, ECDSA or Ed25519)
// and signing short-lived SSH user certificates bound to Ziti identities.
package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// LoadKey reads the CA private key from path and returns an ssh.Signer and the
// corresponding ssh.PublicKey. It accepts any key ssh.ParsePrivateKey does —
// PEM-encoded RSA, ECDSA or Ed25519 (PKCS#1, PKCS#8, SEC 1 or OpenSSH format).
// In production this is the Ziti controller's intermediate CA key (never the
// offline root CA key); on stock controllers it is typically RSA.
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
// ttl controls validity duration (the CA defaults to 5 minutes).
// sourceAddress, when non-empty, is set as the "source-address" critical
// option (see ParseSourceAddress and DefaultSourceAddress); "" omits it.
// extensions are the certificate extensions (permissions) to grant, as
// returned by ParseExtensions.
//
// The returned bytes are in authorized_keys format, ready to write to a
// ~/.ssh/<key>-cert.pub file.
func SignCert(signer ssh.Signer, pubKey ssh.PublicKey, identity, principal string, ttl time.Duration, sourceAddress string, extensions []string) ([]byte, error) {
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
			Extensions: map[string]string{},
		},
	}
	for _, e := range extensions {
		cert.Permissions.Extensions[e] = ""
	}
	if sourceAddress != "" {
		// sshd accepts the certificate only from these addresses. Every
		// legitimate login reaches sshd from the host's own ziti-ssh-host
		// proxy over loopback, so this confines certificates to the Ziti path.
		cert.Permissions.CriticalOptions = map[string]string{"source-address": sourceAddress}
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

// reservedUsernames are Linux account names that must never be issued as a
// per-identity certificate principal by ziti-ssh-ca, nor managed by
// ziti-ssh-host: root, common Debian/Ubuntu system accounts, the default
// cloud-image user, and generic administrator names. ziti-ssh-host's ownership
// registry is the primary control; this list is defence in depth on both sides.
var reservedUsernames = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "gnats": true, "nobody": true, "systemd-network": true,
	"systemd-resolve": true, "systemd-timesync": true, "messagebus": true,
	"syslog": true, "sshd": true, "ubuntu": true, "admin": true, "ziti": true,
}

// IsReservedUsername reports whether username is on the reserved list.
func IsReservedUsername(username string) bool {
	return reservedUsernames[username]
}

// ValidatePerIdentityPrincipal rejects derived per-identity principals that
// must never appear in a certificate: empty, reserved names (see
// IsReservedUsername, including "root"), or names starting with '-' (which
// command-line tools would parse as an option). A certificate for a reserved
// name would be accepted by sshd on any host trusting the CA where that
// account exists, independent of ziti-ssh-host's own checks.
func ValidatePerIdentityPrincipal(principal string) error {
	switch {
	case principal == "":
		return fmt.Errorf("derived principal is empty")
	case IsReservedUsername(principal):
		return fmt.Errorf("derived principal %q is a reserved account name", principal)
	case strings.HasPrefix(principal, "-"):
		return fmt.Errorf("derived principal %q must not start with '-'", principal)
	}
	return nil
}

// DefaultSourceAddress is the default "source-address" critical option: the
// loopback addresses from which ziti-ssh-host proxies connections to sshd.
const DefaultSourceAddress = "127.0.0.1/32,::1/128"

// ParseSourceAddress validates and normalises a value for the certificate
// "source-address" critical option: a comma-separated list of IP addresses or
// CIDR blocks. A bare IP becomes a /32 (IPv4) or /128 (IPv6). CIDRs with host
// bits set are rejected to avoid silently widening the range. The value
// "none" disables the option and returns "".
func ParseSourceAddress(v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "none") {
		return "", nil
	}
	if v == "" {
		return "", fmt.Errorf("source address list is empty (use \"none\" to disable)")
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return "", fmt.Errorf("source address list %q has an empty entry", v)
		}
		if strings.Contains(item, "/") {
			ip, ipnet, err := net.ParseCIDR(item)
			if err != nil {
				return "", fmt.Errorf("invalid CIDR %q: %w", item, err)
			}
			if !ip.Equal(ipnet.IP) {
				return "", fmt.Errorf("CIDR %q has host bits set (did you mean %s?)", item, ipnet.String())
			}
			out = append(out, ipnet.String())
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			return "", fmt.Errorf("invalid IP address %q", item)
		}
		if ip.To4() != nil {
			out = append(out, ip.To4().String()+"/32")
		} else {
			out = append(out, ip.String()+"/128")
		}
	}
	return strings.Join(out, ","), nil
}

// MinRSABits is the smallest RSA client key the CA will certify.
const MinRSABits = 3072

// allowedClientKeyTypes are the SSH public key algorithms the CA certifies.
var allowedClientKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoRSA:        true,
}

// ValidateClientKey rejects keys the CA must not certify: certificates,
// DSA and other unsupported algorithms, RSA keys shorter than MinRSABits, and
// the CA's own public key.
func ValidateClientKey(key, caKey ssh.PublicKey) error {
	if _, isCert := key.(*ssh.Certificate); isCert {
		return fmt.Errorf("a certificate was submitted; send the plain public key")
	}
	if !allowedClientKeyTypes[key.Type()] {
		return fmt.Errorf("key type %s is not supported (use ed25519, ecdsa, or rsa >= %d bits)", key.Type(), MinRSABits)
	}
	if key.Type() == ssh.KeyAlgoRSA {
		cpk, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return fmt.Errorf("cannot inspect RSA key")
		}
		rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < MinRSABits {
			bits := 0
			if ok {
				bits = rk.N.BitLen()
			}
			return fmt.Errorf("RSA key is %d bits; at least %d required", bits, MinRSABits)
		}
	}
	if caKey != nil && bytes.Equal(key.Marshal(), caKey.Marshal()) {
		return fmt.Errorf("refusing to certify the CA's own key")
	}
	return nil
}

// DefaultExtensions are the certificate extensions granted by default:
// interactive terminals and port forwarding (ziti-ssh -L/-R/-D). Agent
// forwarding is not granted by default: clients cannot yet verify which host
// they reached (see the H8 notes in docs/operations.md).
const DefaultExtensions = "permit-pty,permit-port-forwarding"

// knownExtensions are the OpenSSH user-certificate extensions.
var knownExtensions = map[string]bool{
	"permit-pty":              true,
	"permit-port-forwarding":  true,
	"permit-agent-forwarding": true,
	"permit-X11-forwarding":   true,
	"permit-user-rc":          true,
	"no-touch-required":       true,
}

// ParseExtensions validates a comma-separated list of certificate extensions.
// "none" grants no extensions (no PTY, no forwarding).
func ParseExtensions(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "none") {
		return []string{}, nil
	}
	if v == "" {
		return nil, fmt.Errorf("extension list is empty (use \"none\" to grant no extensions)")
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range strings.Split(v, ",") {
		e = strings.TrimSpace(e)
		if !knownExtensions[e] {
			return nil, fmt.Errorf("unknown certificate extension %q", e)
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out, nil
}
