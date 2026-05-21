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

// OIDC support for ziti-ssh — thin wrappers around internal/oidc so the rest
// of main.go can use the same short names it always has.

import (
	zitioidc "github.com/netfoundry/ziti-ssh/internal/oidc"
	ziti "github.com/openziti/sdk-golang/ziti"
)

const defaultCallbackPort = zitioidc.DefaultCallbackPort

type oidcFlowParams = zitioidc.FlowParams

func addOIDCCredentials(zitiCtx ziti.Context, p oidcFlowParams) error {
	return zitioidc.AddCredentials(zitiCtx, p)
}
