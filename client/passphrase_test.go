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
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeEncryptedKey(t *testing.T, pass string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, sshPub
}

func TestNewCertSignerPrompt_AsksForPassphraseWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path, pub := writeEncryptedKey(t, "s3cret")

	// Without a prompt the old behaviour stays: an error naming the agent.
	if _, err := NewCertSigner(path); err == nil {
		t.Fatal("encrypted key loaded without agent or passphrase")
	}

	asked := 0
	signer, err := NewCertSignerPrompt(path, func() ([]byte, error) {
		asked++
		return []byte("s3cret"), nil
	})
	if err != nil {
		t.Fatalf("NewCertSignerPrompt: %v", err)
	}
	if asked != 1 {
		t.Errorf("prompt called %d times", asked)
	}
	if string(signer.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Error("signer has the wrong public key")
	}

	if _, err := NewCertSignerPrompt(path, func() ([]byte, error) { return []byte("wrong"), nil }); err == nil {
		t.Error("wrong passphrase accepted")
	}
}

func TestKnownHosts_RefusesWritableByOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	kh := KnownHosts{Path: path}
	if _, err := kh.read(); err != nil {
		t.Fatalf("0600 refused: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := kh.read(); err == nil {
		t.Fatal("world-writable known_hosts accepted")
	}
}
