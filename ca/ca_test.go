package ca_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/edwardm/ziti-ssh/ca"
)

// generateTestCA creates an ephemeral Ed25519 CA key pair in memory and
// returns an ssh.Signer and the corresponding ssh.PublicKey.
func generateTestCA(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	return signer, signer.PublicKey()
}

// generateTestClientKey creates an ephemeral Ed25519 key pair to use as the
// "client" key that will be signed by the CA.
func generateTestClientKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap client public key: %v", err)
	}
	return sshPub
}

func TestSignCert(t *testing.T) {
	caSigner, _ := generateTestCA(t)
	clientPub := generateTestClientKey(t)

	const identity = "alice@example"
	const principal = "ziggy"
	const ttl = 8 * time.Hour

	before := time.Now()
	certBytes, err := ca.SignCert(caSigner, clientPub, identity, principal, ttl)
	after := time.Now()

	if err != nil {
		t.Fatalf("SignCert returned error: %v", err)
	}
	if len(certBytes) == 0 {
		t.Fatal("SignCert returned empty bytes")
	}

	// Parse the returned authorized_keys line back into a certificate.
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}
	cert, ok := parsedPub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", parsedPub)
	}

	t.Run("CertType", func(t *testing.T) {
		if cert.CertType != ssh.UserCert {
			t.Errorf("CertType = %d, want %d (UserCert)", cert.CertType, ssh.UserCert)
		}
	})

	t.Run("KeyId", func(t *testing.T) {
		wantKeyId := "ziti:" + identity
		if cert.KeyId != wantKeyId {
			t.Errorf("KeyId = %q, want %q", cert.KeyId, wantKeyId)
		}
	})

	t.Run("Principals", func(t *testing.T) {
		if len(cert.ValidPrincipals) != 1 {
			t.Fatalf("len(ValidPrincipals) = %d, want 1", len(cert.ValidPrincipals))
		}
		if cert.ValidPrincipals[0] != principal {
			t.Errorf("ValidPrincipals[0] = %q, want %q", cert.ValidPrincipals[0], principal)
		}
	})

	t.Run("ValidityWindow", func(t *testing.T) {
		validAfter := time.Unix(int64(cert.ValidAfter), 0)
		validBefore := time.Unix(int64(cert.ValidBefore), 0)

		// ValidAfter must be at or after our before-timestamp (with 1s slack for clock granularity).
		if validAfter.Before(before.Add(-time.Second)) {
			t.Errorf("ValidAfter %v is before test start %v", validAfter, before)
		}
		// ValidAfter must not be in the future relative to after.
		if validAfter.After(after.Add(time.Second)) {
			t.Errorf("ValidAfter %v is after test end %v", validAfter, after)
		}

		// ValidBefore must be approximately now+8h (within 5 seconds).
		expectedBefore := before.Add(ttl)
		diff := validBefore.Sub(expectedBefore)
		if diff < -5*time.Second || diff > 5*time.Second {
			t.Errorf("ValidBefore %v is not within 5s of expected %v", validBefore, expectedBefore)
		}
	})

	t.Run("Extensions", func(t *testing.T) {
		required := []string{
			"permit-pty",
			"permit-port-forwarding",
			"permit-agent-forwarding",
		}
		for _, ext := range required {
			if _, ok := cert.Extensions[ext]; !ok {
				t.Errorf("missing extension %q", ext)
			}
		}
	})
}

func TestSignCert_EmptyIdentityRejected(t *testing.T) {
	caSigner, _ := generateTestCA(t)
	clientPub := generateTestClientKey(t)

	_, err := ca.SignCert(caSigner, clientPub, "", "ziggy", 8*time.Hour)
	if err == nil {
		t.Fatal("expected error for empty identity, got nil")
	}
}

func TestSignCert_EmptyPrincipalRejected(t *testing.T) {
	caSigner, _ := generateTestCA(t)
	clientPub := generateTestClientKey(t)

	_, err := ca.SignCert(caSigner, clientPub, "alice", "", 8*time.Hour)
	if err == nil {
		t.Fatal("expected error for empty principal, got nil")
	}
}

func TestDeriveUsername(t *testing.T) {
	tests := []struct {
		name     string
		identity string
		want     string
	}{
		{
			name:     "already valid lowercase",
			identity: "alice",
			want:     "alice",
		},
		{
			name:     "uppercase letters are lowercased",
			identity: "Alice",
			want:     "alice",
		},
		{
			name:     "all uppercase",
			identity: "ALICE",
			want:     "alice",
		},
		{
			name:     "at sign replaced",
			identity: "alice@example.com",
			want:     "alice_example_com",
		},
		{
			name:     "slash replaced",
			identity: "corp/alice",
			want:     "corp_alice",
		},
		{
			name:     "dot replaced",
			identity: "alice.smith",
			want:     "alice_smith",
		},
		{
			name:     "space replaced",
			identity: "alice smith",
			want:     "alice_smith",
		},
		{
			name:     "mixed special chars",
			identity: "Alice@Corp/SSH.User 1",
			want:     "alice_corp_ssh_user_1",
		},
		{
			name:     "starts with digit gets z prefix",
			identity: "123alice",
			want:     "z123alice",
		},
		{
			name:     "starts with single digit gets z prefix",
			identity: "9user",
			want:     "z9user",
		},
		{
			name:     "truncated to 32 chars",
			identity: "this-is-a-very-long-identity-name-that-exceeds-32-characters",
			want:     "this-is-a-very-long-identity-nam",
		},
		{
			name:     "truncation after digit-prefix still 32 chars",
			identity: "9abcdefghijklmnopqrstuvwxyz01234",
			// lowercased: "9abcdefghijklmnopqrstuvwxyz01234" (32 chars), digit start → "z9abcdefghijklmnopqrstuvwxyz0123" (33 → truncate to 32)
			want: "z9abcdefghijklmnopqrstuvwxyz0123",
		},
		{
			name:     "hyphen and underscore preserved",
			identity: "alice_smith-dev",
			want:     "alice_smith-dev",
		},
		{
			name:     "digits in middle preserved",
			identity: "worker42",
			want:     "worker42",
		},
		{
			name:     "already exactly 32 chars unchanged",
			identity: "abcdefghijklmnopqrstuvwxyz012345",
			want:     "abcdefghijklmnopqrstuvwxyz012345",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ca.DeriveUsername(tc.identity)
			if got != tc.want {
				t.Errorf("DeriveUsername(%q) = %q, want %q", tc.identity, got, tc.want)
			}
			// Invariants that must hold for every output.
			if len(got) > 32 {
				t.Errorf("result %q is longer than 32 chars (%d)", got, len(got))
			}
			if len(got) > 0 && got[0] >= '0' && got[0] <= '9' {
				t.Errorf("result %q starts with a digit", got)
			}
		})
	}
}

func TestPublicKeyBytes(t *testing.T) {
	_, caPub := generateTestCA(t)

	b := ca.PublicKeyBytes(caPub)
	if len(b) == 0 {
		t.Fatal("PublicKeyBytes returned empty slice")
	}
	// authorized_keys lines begin with the key type.
	if !strings.HasPrefix(string(b), "ssh-ed25519 ") {
		t.Errorf("PublicKeyBytes = %q, want prefix %q", string(b), "ssh-ed25519 ")
	}
}
