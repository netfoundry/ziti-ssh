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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fullsailor/pkcs7"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCert(t *testing.T, cn string, parent *testCert, isCA bool) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCert{cert: c, key: key}
}

// controllerServer is a TLS server whose certificate is issued by serverCA and
// whose /.well-known/est/cacerts advertises bundleCA.
func controllerServer(t *testing.T, serverCA, bundleCA *testCert) string {
	t.Helper()
	leaf := newCert(t, "controller", serverCA, false)
	p7, err := pkcs7.DegenerateCertificate(bundleCA.cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/est/cacerts" {
			_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(p7)))
			return
		}
		http.NotFound(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.cert.Raw}, PrivateKey: leaf.key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func opts(t *testing.T, host string) controllerTrustOptions {
	return controllerTrustOptions{host: host, cacheDir: t.TempDir(), out: &bytes.Buffer{}}
}

func TestControllerTrust_FirstUse(t *testing.T) {
	ca := newCert(t, "ziti-root", nil, true)
	host := controllerServer(t, ca, ca)

	t.Run("non-interactive without --yes refuses", func(t *testing.T) {
		o := opts(t, host)
		if _, err := controllerTLSConfig(o); err == nil {
			t.Fatal("untrusted controller accepted silently")
		}
		if _, err := os.Stat(cachedBundlePath(o.cacheDir, host)); err == nil {
			t.Error("bundle saved without consent")
		}
	})

	t.Run("--yes saves and trusts; next run uses the saved bundle", func(t *testing.T) {
		o := opts(t, host)
		o.yes = true
		cfg, err := controllerTLSConfig(o)
		if err != nil || cfg.RootCAs == nil {
			t.Fatalf("cfg=%v err=%v", cfg, err)
		}
		fi, err := os.Stat(cachedBundlePath(o.cacheDir, host))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("saved bundle: %v %v", fi, err)
		}
		o.yes = false
		if _, err := controllerTLSConfig(o); err != nil {
			t.Errorf("saved bundle not used: %v", err)
		}
	})

	t.Run("interactive yes", func(t *testing.T) {
		o := opts(t, host)
		asked := ""
		o.confirm = func(q string) bool { asked = q; return true }
		if _, err := controllerTLSConfig(o); err != nil || !strings.Contains(asked, "Trust") {
			t.Fatalf("asked=%q err=%v", asked, err)
		}
	})
}

func TestControllerTrust_ChangedCARequiresConfirmation(t *testing.T) {
	newCA := newCert(t, "new-root", nil, true)
	host := controllerServer(t, newCA, newCA)
	oldCA := newCert(t, "old-root", nil, true)

	setup := func(t *testing.T) controllerTrustOptions {
		o := opts(t, host)
		if err := os.MkdirAll(o.cacheDir, 0o700); err != nil {
			t.Fatal(err)
		}
		pemOld := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oldCA.cert.Raw})
		if err := os.WriteFile(cachedBundlePath(o.cacheDir, host), pemOld, 0o600); err != nil {
			t.Fatal(err)
		}
		return o
	}

	t.Run("--yes does not replace", func(t *testing.T) {
		o := setup(t)
		o.yes = true
		if _, err := controllerTLSConfig(o); err == nil {
			t.Fatal("changed CA replaced by --yes")
		}
		if !strings.Contains(o.out.(*bytes.Buffer).String(), "does NOT match") {
			t.Error("no mismatch warning")
		}
	})

	t.Run("interactive confirmation replaces", func(t *testing.T) {
		o := setup(t)
		o.confirm = func(string) bool { return true }
		if _, err := controllerTLSConfig(o); err != nil {
			t.Fatalf("confirmed replacement failed: %v", err)
		}
		b, _ := os.ReadFile(cachedBundlePath(o.cacheDir, host))
		blk, _ := pem.Decode(b)
		if blk == nil || !bytes.Equal(blk.Bytes, newCA.cert.Raw) {
			t.Error("saved bundle not replaced with the controller's current CA")
		}
	})
}

func TestControllerTrust_BundleMustIssueServerCert(t *testing.T) {
	realCA := newCert(t, "real", nil, true)
	otherCA := newCert(t, "other", nil, true)
	host := controllerServer(t, realCA, otherCA) // advertises a CA that did not issue its cert
	o := opts(t, host)
	o.yes = true
	if _, err := controllerTLSConfig(o); err == nil {
		t.Fatal("bundle that does not issue the server certificate was trusted")
	}
}

func TestControllerTrust_InsecureWarns(t *testing.T) {
	o := opts(t, "127.0.0.1:1")
	o.insecure = true
	cfg, err := controllerTLSConfig(o)
	if err != nil || !cfg.InsecureSkipVerify {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
	if !strings.Contains(o.out.(*bytes.Buffer).String(), "NOT verified") {
		t.Error("no warning for --insecure")
	}
}

func TestResolveControllerOptions_PasswordSources(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ZITI_CTRL_PASSWORD", "")
	t.Setenv("ZITI_CTRL_PASSWORD_FILE", "")

	f := t.TempDir() + "/admin-secret"
	if err := os.WriteFile(f, []byte("test-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := resolveControllerOptions("ctrl", "admin", "", f, "", false, false)
	if err != nil || o.pass != "test-value" {
		t.Fatalf("--password-file: pass=%q err=%v", o.pass, err)
	}

	t.Setenv("ZITI_CTRL_PASSWORD", "from-env")
	if o, err = resolveControllerOptions("ctrl", "admin", "", "", "", false, false); err != nil || o.pass != "from-env" {
		t.Fatalf("env: pass=%q err=%v", o.pass, err)
	}

	t.Setenv("ZITI_CTRL_PASSWORD", "")
	if _, err := resolveControllerOptions("ctrl", "admin", "", "", "", false, false); err == nil {
		t.Fatal("missing password accepted (tests run without a terminal, so no prompt)")
	}
	if _, err := resolveControllerOptions("ctrl", "admin", "x", "", "ca.pem", true, false); err == nil {
		t.Fatal("--insecure with --controller-ca accepted")
	}
}
