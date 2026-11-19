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

// Package oidc implements the browser-based OIDC authorization code flow used
// by ziti-ssh and ziti-scp to satisfy ext-jwt-signer policies on a Ziti
// controller.
//
// When an OIDC issuer is configured, the flow first claims the callback port on
// both loopback addresses (127.0.0.1 and ::1) — refusing to continue if
// another process already holds it, since that process would receive the
// login — then opens the browser to the authorization URL and waits for the
// identity provider to redirect back with an authorization code. The code is
// exchanged for an access token which is added to the Ziti context credentials
// before Authenticate() is called.
//
// If no client secret is provided PKCE is used automatically (public client).
package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	ziti "github.com/openziti/sdk-golang/ziti"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	// DefaultCallbackPort is the localhost port used for the OIDC redirect URI
	// when no explicit port is configured.
	DefaultCallbackPort = "63275"

	callbackPath      = "/auth/callback"
	defaultAuthScopes = "openid profile email"
	flowTimeout       = 2 * time.Minute
)

// FlowParams holds all parameters required to run the OIDC browser flow.
type FlowParams struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	CallbackPort string
}

// AddCredentials runs the OIDC browser flow (if Issuer is set) and adds the
// resulting access token to zitiCtx as a secondary JWT credential. This
// satisfies ext-jwt-signer authentication policies on the Ziti controller.
//
// If FlowParams.Issuer is empty the function returns nil immediately and the
// caller proceeds with certificate-only Ziti auth.
//
// Call after ziti.NewContext* and before zitiCtx.Authenticate().
func AddCredentials(zitiCtx ziti.Context, p FlowParams) error {
	if p.Issuer == "" {
		return nil
	}

	token, err := runFlow(context.Background(), p)
	if err != nil {
		return fmt.Errorf("OIDC authentication failed: %w", err)
	}

	// AddJWT satisfies the secondary authentication requirement imposed by an
	// ext-jwt-signer policy. Primary auth (mTLS via the enrolled Ziti identity)
	// and the JWT secondary auth are both presented during Authenticate().
	zitiCtx.GetCredentials().AddJWT(token)
	slog.Info("OIDC token added to Ziti credentials", "issuer", p.Issuer)
	return nil
}

// runFlow performs the browser-based OIDC authorization code (+ optional PKCE)
// flow and returns the access token.
func runFlow(ctx context.Context, p FlowParams) (string, error) {
	if p.Issuer == "" {
		return "", errors.New("OIDC issuer URL must not be empty")
	}
	if p.ClientID == "" {
		return "", errors.New("OIDC client ID must not be empty")
	}
	if p.CallbackPort == "" {
		p.CallbackPort = DefaultCallbackPort
	}

	// Claim the callback port before contacting the identity provider or
	// opening the browser. If another process (e.g. another local user) held
	// it, the browser would deliver the login to that process.
	listeners, err := listenLoopback(p.CallbackPort)
	if err != nil {
		return "", err
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	redirectURL := fmt.Sprintf("http://localhost:%s%s", p.CallbackPort, callbackPath)

	cookieHandler := httphelper.NewCookieHandler(
		securecookie.GenerateRandomKey(32),
		securecookie.GenerateRandomKey(32),
		httphelper.WithUnsecure(),
	)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	if p.ClientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	flowCtx, cancel := context.WithTimeout(ctx, flowTimeout)
	defer cancel()

	scopes := strings.Split(defaultAuthScopes, " ")
	relyingParty, err := rp.NewRelyingPartyOIDC(
		flowCtx,
		p.Issuer,
		p.ClientID,
		p.ClientSecret,
		redirectURL,
		scopes,
		options...,
	)
	if err != nil {
		return "", fmt.Errorf("create OIDC relying party for %q: %w", p.Issuer, err)
	}

	tokenChan := make(chan *oidc.Tokens[*oidc.IDTokenClaims], 1)

	callback := func(
		w http.ResponseWriter,
		r *http.Request,
		tokens *oidc.Tokens[*oidc.IDTokenClaims],
		state string,
		party rp.RelyingParty,
	) {
		// Only the first callback is used; later ones must not block.
		offer(tokenChan, tokens)
		_, _ = w.Write([]byte(
			"<script>window.close()</script>" +
				"<body onload=\"window.close()\">" +
				"<strong>Authentication successful.</strong>" +
				" You may close this window and return to the terminal." +
				"</body>",
		))
	}

	mux := http.NewServeMux()
	mux.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp.AuthURLHandler(rand.Text, relyingParty)(w, r)
	}))
	mux.Handle(callbackPath, rp.CodeExchangeHandler(callback, relyingParty))

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	for _, l := range listeners {
		go func(l net.Listener) {
			if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("OIDC callback server error", "addr", l.Addr(), "err", err)
			}
		}(l)
	}

	go func() {
		<-flowCtx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutCtx); err != nil {
			slog.Debug("OIDC callback server shutdown", "err", err)
		}
	}()

	slog.Info("OIDC flow started; opening browser",
		"issuer", p.Issuer,
		"callback_port", p.CallbackPort,
		"timeout", flowTimeout,
	)
	openBrowser("http://localhost:"+p.CallbackPort+"/login", os.Stderr, startCommand)

	select {
	case tokens := <-tokenChan:
		slog.Info("OIDC authentication succeeded")
		return tokens.AccessToken, nil
	case <-flowCtx.Done():
		return "", fmt.Errorf("OIDC authentication timed out after %s", flowTimeout)
	}
}

// listenLoopback binds the callback port on 127.0.0.1 and, when the host has
// an IPv6 loopback, on ::1. Browsers may resolve "localhost" to either, so
// both must be held by this process. It fails if either address is already in
// use. It never binds a non-loopback address.
func listenLoopback(port string) ([]net.Listener, error) {
	l4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, callbackPortError(port, "127.0.0.1", err)
	}
	if !ipv6LoopbackAvailable() {
		slog.Debug("IPv6 loopback unavailable; OIDC callback listening on 127.0.0.1 only")
		return []net.Listener{l4}, nil
	}
	l6, err := net.Listen("tcp6", net.JoinHostPort("::1", port))
	if err != nil {
		_ = l4.Close()
		return nil, callbackPortError(port, "::1", err)
	}
	return []net.Listener{l4, l6}, nil
}

// ipv6LoopbackAvailable reports whether ::1 can be bound at all. If it cannot,
// no other process can bind it either, so listening on IPv4 only is safe.
func ipv6LoopbackAvailable() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func callbackPortError(port, addr string, err error) error {
	return fmt.Errorf("OIDC callback port %s on %s is unavailable (%v); refusing to continue because "+
		"another process holding it would receive the login. Stop that process or set a different "+
		"callback port (oidc.callback_port) that is also registered with the identity provider", port, addr, err)
}

// startCommand starts an external program without waiting for it to finish.
func startCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// openBrowser prints the login URL to w first, so it is always available on
// headless machines, then tries to open it in the user's browser. Failure to
// launch a browser is reported but is not fatal.
func openBrowser(url string, w io.Writer, start func(name string, args ...string) error) {
	_, _ = fmt.Fprintf(w, "To sign in, open this URL in a browser (attempting to open it for you):\n  %s\n", url)

	var err error
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "netbsd":
		err = start("xdg-open", url)
	case "darwin":
		err = start("open", url)
	case "windows":
		err = start("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		err = fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
	if err != nil {
		_, _ = fmt.Fprintf(w, "Could not open a browser (%v); open the URL above manually.\n", err)
	}
}

// offer sends v on ch without blocking and reports whether it was delivered.
func offer[T any](ch chan T, v T) bool {
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}
