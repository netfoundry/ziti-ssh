// Package oidc implements the browser-based OIDC authorization code flow used
// by ziti-ssh and ziti-scp to satisfy ext-jwt-signer policies on a Ziti
// controller.
//
// When an OIDC issuer is configured, the flow opens a temporary localhost HTTP
// server, opens the browser to the authorization URL, and waits for the
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
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	ziti "github.com/openziti/sdk-golang/ziti"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rp/cli"
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
		tokenChan <- tokens
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
		rp.AuthURLHandler(func() string {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
		}, relyingParty)(w, r)
	}))
	mux.Handle(callbackPath, rp.CodeExchangeHandler(callback, relyingParty))

	server := &http.Server{
		Addr:    ":" + p.CallbackPort,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("OIDC callback server error", "err", err)
		}
	}()

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
	cli.OpenBrowser("http://localhost:" + p.CallbackPort + "/login")

	select {
	case tokens := <-tokenChan:
		slog.Info("OIDC authentication succeeded")
		return tokens.AccessToken, nil
	case <-flowCtx.Done():
		return "", fmt.Errorf("OIDC authentication timed out after %s", flowTimeout)
	}
}
