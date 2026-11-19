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
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fullsailor/pkcs7"
)

// Controller TLS trust for "ziti-ssh-ca config apply|remove".
//
// Resolution order (mirrors "ziti edge login"):
//  1. --controller-ca <file>
//  2. a bundle saved earlier for this controller
//  3. the system CA pool, if it already trusts the controller
//  4. the controller's own CA bundle from /.well-known/est/cacerts, checked
//     against the server's TLS chain, shown to the user and saved after
//     confirmation (or --yes)
//
// A saved bundle that no longer matches the server is a warning sign: it is
// only replaced after interactive confirmation, never by --yes alone.
// --insecure skips verification entirely and prints a warning.

// trustPrompt asks a yes/no question; nil means non-interactive.
type trustPrompt func(question string) bool

type controllerTrustOptions struct {
	host     string // host:port
	caPath   string // --controller-ca
	insecure bool   // --insecure
	yes      bool   // --yes: accept a first-seen controller CA without asking
	cacheDir string // where accepted bundles are saved
	confirm  trustPrompt
	out      io.Writer // messages (stderr)
}

// defaultControllerCADir returns $XDG_CONFIG_HOME/ziti-ssh/controllers.
func defaultControllerCADir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "ziti-ssh", "controllers"), nil
}

func cachedBundlePath(dir, host string) string {
	return filepath.Join(dir, strings.NewReplacer(":", "_", "/", "_").Replace(host)+".pem")
}

// controllerTLSConfig returns the TLS configuration for talking to the
// controller's management API.
func controllerTLSConfig(o controllerTrustOptions) (*tls.Config, error) {
	serverName, _, err := net.SplitHostPort(o.host)
	if err != nil {
		return nil, fmt.Errorf("controller address %q: %w", o.host, err)
	}
	out := o.out
	if out == nil {
		out = io.Discard
	}

	if o.insecure {
		fmt.Fprintln(out, "WARNING: --insecure: the controller's TLS certificate is NOT verified; the admin password is sent to whoever answers.")
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // operator-explicit flag
	}

	if o.caPath != "" {
		pool, err := loadPEMPool(o.caPath)
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool, ServerName: serverName}, nil
	}

	cache := cachedBundlePath(o.cacheDir, o.host)
	if _, err := os.Stat(cache); err == nil {
		pool, err := loadPEMPool(cache)
		if err != nil {
			return nil, err
		}
		if probeErr := probeTLS(o.host, serverName, pool); probeErr == nil {
			return &tls.Config{RootCAs: pool, ServerName: serverName}, nil
		} else if !isVerificationError(probeErr) {
			return nil, fmt.Errorf("connect to controller %s: %w", o.host, probeErr)
		}
		// The controller no longer chains to the saved bundle.
		bundle, certs, err := fetchControllerBundle(o.host, serverName)
		if err != nil {
			return nil, fmt.Errorf("controller %s does not match its saved CA bundle %s, and its current bundle could not be fetched: %w", o.host, cache, err)
		}
		fmt.Fprintf(out, "WARNING: controller %s presents a certificate authority that does NOT match the saved bundle %s.\n"+
			"This is expected only if the controller's PKI was replaced. Server-provided certificate authorities:\n", o.host, cache)
		describeCerts(out, certs)
		if o.confirm == nil || !o.confirm("Replace the saved certificate authority? [y/N] ") {
			return nil, fmt.Errorf("controller CA for %s changed; not replacing %s (use --controller-ca, or confirm interactively)", o.host, cache)
		}
		return saveAndUse(o, cache, serverName, bundle, out)
	}

	if probeTLS(o.host, serverName, nil) == nil {
		return &tls.Config{ServerName: serverName}, nil // trusted by the system pool
	}

	bundle, certs, err := fetchControllerBundle(o.host, serverName)
	if err != nil {
		return nil, fmt.Errorf("controller %s is not trusted by the system CAs, and its CA bundle could not be fetched: %w (use --controller-ca)", o.host, err)
	}
	fmt.Fprintf(out, "Untrusted certificate authority retrieved from controller %s.\n"+
		"Verified that the controller's TLS certificate is issued by it. Server-provided certificate authorities:\n", o.host)
	describeCerts(out, certs)
	accept := o.yes
	if !accept && o.confirm != nil {
		accept = o.confirm("Trust this controller certificate authority? [y/N] ")
	}
	if !accept {
		return nil, fmt.Errorf("controller CA for %s not trusted (re-run interactively, add --yes, or use --controller-ca)", o.host)
	}
	return saveAndUse(o, cache, serverName, bundle, out)
}

func saveAndUse(o controllerTrustOptions, cache, serverName string, bundle []byte, out io.Writer) (*tls.Config, error) {
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cache, bundle, 0o600); err != nil {
		return nil, fmt.Errorf("save controller CA bundle: %w", err)
	}
	fmt.Fprintf(out, "Saved controller certificate authority to %s\n", cache)
	pool, err := loadPEMPool(cache)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName}, nil
}

// fetchControllerBundle downloads the controller's CA bundle (base64 PKCS#7
// from /.well-known/est/cacerts) without verification, then requires the
// controller's TLS certificate to chain to it. It returns the bundle as PEM.
func fetchControllerBundle(host, serverName string) ([]byte, []*x509.Certificate, error) {
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // bootstrap; verified below
	}
	resp, err := client.Get("https://" + host + "/.well-known/est/cacerts")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET /.well-known/est/cacerts: %s", resp.Status)
	}
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, nil, fmt.Errorf("decode CA bundle: %w", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA bundle: %w", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, nil, errors.New("CA bundle is empty")
	}
	var buf bytes.Buffer
	pool := x509.NewCertPool()
	for _, c := range p7.Certificates {
		pool.AddCert(c)
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	if err := probeTLS(host, serverName, pool); err != nil {
		return nil, nil, fmt.Errorf("controller's TLS certificate is not issued by its own CA bundle: %w", err)
	}
	return buf.Bytes(), p7.Certificates, nil
}

func describeCerts(out io.Writer, certs []*x509.Certificate) {
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		fmt.Fprintf(out, "  subject: %s\n  SHA-256: %X\n", c.Subject.String(), sum[:])
	}
}

// probeTLS performs a TLS handshake verifying the server against pool (the
// system pool when nil).
func probeTLS(host, serverName string, pool *x509.CertPool) error {
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", host, &tls.Config{RootCAs: pool, ServerName: serverName})
	if err != nil {
		return err
	}
	return conn.Close()
}

func isVerificationError(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	return errors.As(err, &cv) || errors.As(err, &ua)
}

func loadPEMPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no valid PEM certificates found in %q", path)
	}
	return pool, nil
}

// lineReader reads one line from r with the trailing newline removed.
func lineReader(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
