package main

// OIDC authentication flow for ziti-ssh.
//
// When --oidc-issuer is set (or oidc.issuer in the config file), the connect
// and sign commands run a local browser-based OIDC auth flow before dialling
// any Ziti service. The resulting access token is added to the Ziti context
// credentials as a secondary JWT, satisfying ext-jwt-signer policies on the
// controller.
//
// The implementation follows the pattern established in the zssh reference
// client (zssh/zsshlib/oidc.go and zssh/zsshlib/authenticate.go).

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
	defaultCallbackPort = "63275"
	callbackPath        = "/auth/callback"
	defaultAuthScopes   = "openid profile email"
	oidcFlowTimeout     = 2 * time.Minute
)

// oidcFlowParams holds all parameters required to run the OIDC browser flow.
type oidcFlowParams struct {
	issuer       string
	clientID     string
	clientSecret string
	callbackPort string
}

// runOIDCFlow performs the browser-based OIDC authorization code (+ optional
// PKCE) flow and returns the access token. It blocks until the user completes
// authentication in the browser or the flow times out.
//
// A temporary HTTP server is started on localhost:<callbackPort> to receive
// the authorization code redirect. The browser is opened automatically.
func runOIDCFlow(ctx context.Context, p oidcFlowParams) (string, error) {
	if p.issuer == "" {
		return "", errors.New("OIDC issuer URL must not be empty")
	}
	if p.clientID == "" {
		return "", errors.New("OIDC client ID must not be empty")
	}
	if p.callbackPort == "" {
		p.callbackPort = defaultCallbackPort
	}

	redirectURL := fmt.Sprintf("http://localhost:%s%s", p.callbackPort, callbackPath)

	// Random keys for the secure cookie handler (generated fresh each run;
	// these are ephemeral and do not need to be persisted).
	cookieHandler := httphelper.NewCookieHandler(
		securecookie.GenerateRandomKey(32),
		securecookie.GenerateRandomKey(32),
		httphelper.WithUnsecure(),
	)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	if p.clientSecret == "" {
		// No client secret — use PKCE.
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	flowCtx, cancel := context.WithTimeout(ctx, oidcFlowTimeout)
	defer cancel()

	scopes := strings.Split(defaultAuthScopes, " ")
	relyingParty, err := rp.NewRelyingPartyOIDC(
		flowCtx,
		p.issuer,
		p.clientID,
		p.clientSecret,
		redirectURL,
		scopes,
		options...,
	)
	if err != nil {
		return "", fmt.Errorf("create OIDC relying party for %q: %w", p.issuer, err)
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
			// State is a random UUID-like value; use a simple approach here.
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
		}, relyingParty)(w, r)
	}))
	mux.Handle(callbackPath, rp.CodeExchangeHandler(callback, relyingParty))

	server := &http.Server{
		Addr:    ":" + p.callbackPort,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("OIDC callback server error", "err", err)
		}
	}()

	// Shut the HTTP server down when the flow context ends.
	go func() {
		<-flowCtx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutCtx); err != nil {
			slog.Debug("OIDC callback server shutdown", "err", err)
		}
	}()

	slog.Info("OIDC flow started; opening browser",
		"issuer", p.issuer,
		"callback_port", p.callbackPort,
		"timeout", oidcFlowTimeout,
	)
	cli.OpenBrowser("http://localhost:" + p.callbackPort + "/login")

	select {
	case tokens := <-tokenChan:
		slog.Info("OIDC authentication succeeded")
		return tokens.AccessToken, nil
	case <-flowCtx.Done():
		return "", fmt.Errorf("OIDC authentication timed out after %s", oidcFlowTimeout)
	}
}

// addOIDCCredentials runs the OIDC browser flow (if an issuer is configured)
// and adds the resulting access token to zitiCtx as a secondary JWT credential.
// This satisfies ext-jwt-signer authentication policies on the Ziti controller.
//
// If p.issuer is empty no OIDC flow is run and the function returns nil
// immediately — the caller proceeds with certificate-only Ziti auth.
//
// addOIDCCredentials must be called after ziti.NewContext* and before
// zitiCtx.Authenticate().
func addOIDCCredentials(zitiCtx ziti.Context, p oidcFlowParams) error {
	if p.issuer == "" {
		return nil
	}

	token, err := runOIDCFlow(context.Background(), p)
	if err != nil {
		return fmt.Errorf("OIDC authentication failed: %w", err)
	}

	// AddJWT satisfies the secondary authentication requirement imposed by an
	// ext-jwt-signer policy on the controller. The primary auth (mTLS via the
	// enrolled Ziti identity) and the JWT secondary auth are both presented
	// during zitiCtx.Authenticate().
	zitiCtx.GetCredentials().AddJWT(token)
	slog.Info("OIDC token added to Ziti credentials", "issuer", p.issuer)
	return nil
}
