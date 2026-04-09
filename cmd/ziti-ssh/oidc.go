package main

// OIDC support for ziti-ssh — thin wrappers around internal/oidc so the rest
// of main.go can use the same short names it always has.

import (
	zitioidc "github.com/edwardm/ziti-ssh/internal/oidc"
	ziti "github.com/openziti/sdk-golang/ziti"
)

const defaultCallbackPort = zitioidc.DefaultCallbackPort

type oidcFlowParams = zitioidc.FlowParams

func addOIDCCredentials(zitiCtx ziti.Context, p oidcFlowParams) error {
	return zitioidc.AddCredentials(zitiCtx, p)
}
