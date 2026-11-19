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
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/netfoundry/ziti-ssh/host"
)

func TestServiceState_FailsClosedOnLoadErrors(t *testing.T) {
	var st serviceState
	good := &host.PermissionsConfig{Permissions: map[string]host.IdentityPermissions{"alice": {Groups: []string{"dev"}}}}

	// Startup load failure: unavailable, not "fall back to globals".
	st.update(nil, errors.New("parse error"))
	if _, err := st.current(); err == nil {
		t.Fatal("failed initial load not reported")
	}

	// A good load makes the service available.
	st.update(good, nil)
	if pc, err := st.current(); err != nil || pc != good {
		t.Fatalf("good load: pc=%v err=%v", pc, err)
	}

	// A failed reload must not keep the previous (possibly broader) config.
	st.update(nil, errors.New("bad entry"))
	if pc, err := st.current(); err == nil || pc != nil {
		t.Fatalf("failed reload kept old config: pc=%v err=%v", pc, err)
	}

	// No config attached is not an error: global fallbacks apply.
	st.update(nil, nil)
	if pc, err := st.current(); err != nil || pc != nil {
		t.Fatalf("no config attached: pc=%v err=%v", pc, err)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func makeCert(t *testing.T, subject string, isCA bool, parent *testCA, ip net.IP) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{ip}
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

// A controller endpoint presenting [leaf, rogue CA, real intermediate]. The
// rogue cert has the intermediate's subject but its own key; Go still
// verifies the chain via the real intermediate.
func TestIntCAFromController_UsesVerifiedChain(t *testing.T) {
	root := makeCert(t, "root", true, nil, nil)
	inter := makeCert(t, "intermediate", true, root, nil)
	rogue := makeCert(t, "intermediate", true, nil, nil) // same subject, self-signed, different key
	leaf := makeCert(t, "controller", false, inter, net.IPv4(127, 0, 0, 1))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.cert.Raw, rogue.cert.Raw, inter.cert.Raw},
			PrivateKey:  leaf.key,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	got, err := intCAFromController("https://"+ln.Addr().String(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Raw, inter.cert.Raw) {
		t.Fatalf("picked %q (rogue=%v) instead of the verified intermediate", got.Subject.CommonName, bytes.Equal(got.Raw, rogue.cert.Raw))
	}
}

func authorizedKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
}

func TestMergeTrustedKeys_KeepsKeysOfUnreachableControllers(t *testing.T) {
	a, b, c := authorizedKey(t), authorizedKey(t), authorizedKey(t)
	current := []byte(a + "\n" + b + "\n")
	collected := []clusterCA{{ControllerURL: "x", AuthorizedKey: []byte(a + "\n")}, {ControllerURL: "y", AuthorizedKey: []byte(c + "\n")}}

	got := string(clusterCAsToBytes(mergeTrustedKeys(current, collected)))
	for _, k := range []string{a, b, c} {
		if strings.Count(got, k) != 1 {
			t.Errorf("key missing or duplicated in merged set:\n%s", got)
		}
	}
}
