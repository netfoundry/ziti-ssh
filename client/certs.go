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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// MaxCAResponseBytes bounds the single line read from ziti-ssh-ca. A signed
// certificate in authorized_keys format is a few kilobytes at most.
const MaxCAResponseBytes = 16 * 1024

// CARejectedError is returned when ziti-ssh-ca answers with an
// "error: <reason>" line instead of a certificate (e.g. rate limiting).
type CARejectedError struct {
	Reason string
}

func (e *CARejectedError) Error() string {
	return "CA refused the request: " + e.Reason
}

// ReadCAResponse reads one newline-terminated line from the CA, refusing
// responses longer than MaxCAResponseBytes.
func ReadCAResponse(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, MaxCAResponseBytes+1))
	line, err := br.ReadString('\n')
	if len(line) > MaxCAResponseBytes {
		return "", fmt.Errorf("CA response exceeds %d bytes", MaxCAResponseBytes)
	}
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("read certificate from CA: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// ValidateSignedCert checks the CA's response line before it is written to
// disk. It returns the certificate re-encoded in authorized_keys format.
//
// It fails with *CARejectedError for an "error: ..." reply, and with a plain
// error unless the line is a user certificate for exactly pubKeyLine's key.
// Callers must not overwrite an existing certificate when this fails.
func ValidateSignedCert(line, pubKeyLine string) ([]byte, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("CA returned no certificate")
	}
	if rest, ok := strings.CutPrefix(line, "error:"); ok {
		return nil, &CARejectedError{Reason: strings.TrimSpace(rest)}
	}

	ourKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyLine))
	if err != nil {
		return nil, fmt.Errorf("parse local public key: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("CA response is not a valid certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("CA response is a %s key, not a certificate", pub.Type())
	}
	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("CA returned a host certificate, not a user certificate")
	}
	if !bytes.Equal(cert.Key.Marshal(), ourKey.Marshal()) {
		return nil, errors.New("CA returned a certificate for a different public key")
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

// Refresh threshold bounds: a certificate is refreshed when its remaining
// validity drops below 20% of its total lifetime, capped at maxRefreshWindow
// and never below minRefreshWindow.
const (
	maxRefreshWindow = 5 * time.Minute
	minRefreshWindow = 30 * time.Second
)

// certRefreshThreshold returns how much remaining validity triggers a refresh.
// With the default 5-minute certificates this is 1 minute, so a certificate is
// reused for about 4 minutes instead of being re-signed on every invocation;
// certificates of 25 minutes or longer keep the 5-minute window.
func certRefreshThreshold(cert *ssh.Certificate) time.Duration {
	if cert.ValidAfter == 0 || cert.ValidBefore <= cert.ValidAfter {
		return maxRefreshWindow
	}
	lifetime := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	t := lifetime / 5
	if t > maxRefreshWindow {
		t = maxRefreshWindow
	}
	if t < minRefreshWindow {
		t = minRefreshWindow
	}
	return t
}

// certNeedsRefreshAt reports whether cert should be replaced at time now.
func certNeedsRefreshAt(cert *ssh.Certificate, now time.Time) bool {
	// ValidBefore of 0 or CertTimeInfinity means "forever"; this CA never
	// issues such certificates, but treat them as not needing refresh.
	if cert.ValidBefore == 0 || cert.ValidBefore == ssh.CertTimeInfinity {
		return false
	}
	expiry := time.Unix(int64(cert.ValidBefore), 0)
	return expiry.Sub(now) < certRefreshThreshold(cert)
}

// CertPrincipal returns the only principal of the SSH certificate at
// certPath. ok is false if the file is missing, is not a certificate, or the
// certificate has zero or several principals. Clients use it as the default
// SSH user when none is given: in per-identity mode the CA issues each
// identity a certificate for its derived Linux username, so the user does not
// have to work that name out.
func CertPrincipal(certPath string) (principal string, ok bool) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", false
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", false
	}
	cert, isCert := pub.(*ssh.Certificate)
	if !isCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] == "" {
		return "", false
	}
	return cert.ValidPrincipals[0], true
}
