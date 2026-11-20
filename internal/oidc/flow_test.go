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

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIdP is a minimal OpenID provider: discovery, an authorize endpoint
// that redirects straight back with a code, a token endpoint and its keys.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	pub *rsa.PublicKey // published in the JWKS

	mu            sync.Mutex
	signer        *rsa.PrivateKey // signs ID tokens (normally matches pub)
	tokenIssuer   string          // "iss" in the ID token (normally srv.URL)
	tamperState   bool
	challenge     string
	challengeMeth string
	verifierOK    bool
	secretSeen    string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, pub: &k.PublicKey, signer: k}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.challenge, f.challengeMeth = q.Get("code_challenge"), q.Get("code_challenge_method")
		state := q.Get("state")
		if f.tamperState {
			state += "x"
		}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c1&state="+url.QueryEscape(state), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		if v := r.PostForm.Get("code_verifier"); v != "" {
			sum := sha256.Sum256([]byte(v))
			f.verifierOK = base64.RawURLEncoding.EncodeToString(sum[:]) == f.challenge
		}
		if _, secret, ok := r.BasicAuth(); ok {
			f.secretSeen = secret
		} else if s := r.PostForm.Get("client_secret"); s != "" {
			f.secretSeen = s
		}
		iss := f.tokenIssuer
		if iss == "" {
			iss = f.srv.URL
		}
		now := time.Now()
		claims, _ := json.Marshal(map[string]any{
			"iss": iss, "sub": "alice", "aud": []string{"ziti-ssh"},
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256,
			Key: jose.JSONWebKey{Key: f.signer, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			f.t.Error(err)
			return
		}
		jws, err := signer.Sign(claims)
		if err != nil {
			f.t.Error(err)
			return
		}
		idToken, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token-1", "token_type": "Bearer",
			"expires_in": 3600, "id_token": idToken,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: f.pub, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// runWithBrowser runs runFlow, driving the login with an HTTP client that
// keeps cookies and follows redirects. It returns the token, the flow error
// and the HTTP status the "browser" saw on the callback page.
func runWithBrowser(t *testing.T, p FlowParams, timeout time.Duration) (string, error, int) {
	t.Helper()
	oldBrowse, oldTimeout := browse, flowTimeout
	t.Cleanup(func() { browse, flowTimeout = oldBrowse, oldTimeout })
	flowTimeout = timeout

	status := make(chan int, 1)
	browse = func(u string) {
		go func() {
			jar, _ := cookiejar.New(nil)
			resp, err := (&http.Client{Jar: jar, Timeout: 10 * time.Second}).Get(u)
			if err != nil {
				status <- -1
				return
			}
			resp.Body.Close()
			status <- resp.StatusCode
		}()
	}
	token, err := runFlow(context.Background(), p)
	select {
	case s := <-status:
		return token, err, s
	case <-time.After(5 * time.Second):
		return token, err, 0
	}
}

func TestRunFlow_PKCESuccess(t *testing.T) {
	idp := newFakeIdP(t)
	token, err, status := runWithBrowser(t, FlowParams{Issuer: idp.srv.URL, ClientID: "ziti-ssh", CallbackPort: freePort(t)}, 20*time.Second)
	if err != nil || token != "access-token-1" {
		t.Fatalf("token %q, err %v (callback status %d)", token, err, status)
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if idp.challengeMeth != "S256" || !idp.verifierOK {
		t.Errorf("PKCE not used correctly: method %q, verifier ok %v", idp.challengeMeth, idp.verifierOK)
	}
}

func TestRunFlow_ClientSecretSuccess(t *testing.T) {
	idp := newFakeIdP(t)
	token, err, _ := runWithBrowser(t, FlowParams{Issuer: idp.srv.URL, ClientID: "ziti-ssh", ClientSecret: "s3cret", CallbackPort: freePort(t)}, 20*time.Second)
	if err != nil || token != "access-token-1" {
		t.Fatalf("token %q, err %v", token, err)
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if idp.secretSeen != "s3cret" || idp.challenge != "" {
		t.Errorf("secret %q, challenge %q", idp.secretSeen, idp.challenge)
	}
}

// A rejected callback must not yield a token; the flow keeps waiting (so a
// forged callback cannot end a real login) until it times out.
func TestRunFlow_RejectedCallbacks(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(f *fakeIdP){
		"tampered state": func(f *fakeIdP) { f.tamperState = true },
		"bad signature":  func(f *fakeIdP) { f.signer = other },
		"wrong issuer":   func(f *fakeIdP) { f.tokenIssuer = "https://evil.example" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			mutate(idp)
			token, err, status := runWithBrowser(t, FlowParams{Issuer: idp.srv.URL, ClientID: "ziti-ssh", CallbackPort: freePort(t)}, 3*time.Second)
			if err == nil || token != "" {
				t.Fatalf("accepted: token %q, err %v", token, err)
			}
			if !strings.Contains(err.Error(), "timed out") {
				t.Errorf("err = %v, want timeout", err)
			}
			if status == http.StatusOK {
				t.Errorf("callback page returned 200")
			}
		})
	}
}
