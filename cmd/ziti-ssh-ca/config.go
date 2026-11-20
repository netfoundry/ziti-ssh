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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	management "github.com/openziti/edge-api/rest_management_api_client"
	"github.com/openziti/edge-api/rest_management_api_client/authentication"
	config_client "github.com/openziti/edge-api/rest_management_api_client/config"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/edge-api/rest_util"

	"github.com/netfoundry/ziti-ssh/config"
)

// configTypeSchema is the JSON schema for the ziti-ssh-host.v1 config type.
const configTypeSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["permissions"],
  "properties": {
    "permissions": {
      "type": "object",
      "description": "Map of Ziti identity name to Linux permissions",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "groups": {
            "type": "array",
            "description": "Linux groups to add the user to (must exist on the host)",
            "items": { "type": "string" }
          },
          "sudoers_rule": {
            "type": "string",
            "description": "Rule fragment written after the username in /etc/sudoers.d/ziti-ssh-host-<username>"
          }
        }
      }
    }
  }
}`

// configTypeName is the registered name of the Ziti config type.
const configTypeName = "ziti-ssh-host.v1"

// configTypeFieldTable is the human-readable field table printed by "config print".
const configTypeFieldTable = `Config type: ziti-ssh-host.v1

Fields:
  permissions  (object, required)
    Map of Ziti identity name to per-identity Linux permissions.

    Per-identity properties (all optional):
      groups        (array of string)
        Linux groups to add the ephemeral user to. Each group must already
        exist on the host. Example: ["docker", "sudo"]

      sudoers_rule  (string)
        Rule fragment appended after the username in
        /etc/sudoers.d/ziti-ssh-host-<username>. Example: "ALL=(ALL) NOPASSWD: /usr/bin/apt"

Example config value:
  {
    "permissions": {
      "alice@corp": {
        "groups": ["docker"],
        "sudoers_rule": "ALL=(ALL) NOPASSWD: /usr/bin/systemctl"
      },
      "bob@corp": {
        "groups": []
      }
    }
  }

`

// configCmd is the top-level "config" cobra command. Registered by main.go via
// root.AddCommand(configCmd).
var configCmd = buildConfigCmd()

func buildConfigCmd() *cobra.Command {
	var (
		controllerFlag   string
		usernameFlag     string
		passwordFlag     string
		passwordFileFlag string
		insecureFlag     bool
		controllerCAFlag string
		yesFlag          bool
	)

	parent := &cobra.Command{
		Use:   "config",
		Short: "Manage the ziti-ssh-host.v1 Ziti config type on the controller",
		// No RunE — this parent command has no action of its own.
	}

	parent.PersistentFlags().StringVar(&controllerFlag, "controller", "",
		"Controller host, optionally with port (e.g. ctrl.example.com or ctrl.example.com:8441) (or set ZITI_CTRL_ADDRESS)")
	parent.PersistentFlags().StringVar(&usernameFlag, "username", "",
		"Controller admin username (or set ZITI_CTRL_USERNAME)")
	parent.PersistentFlags().StringVar(&passwordFlag, "password", "",
		"Controller admin password (visible in the process list; prefer --password-file, ZITI_CTRL_PASSWORD, or the prompt)")
	parent.PersistentFlags().StringVar(&passwordFileFlag, "password-file", "",
		"Read the controller admin password from a file, or \"-\" for stdin (or set ZITI_CTRL_PASSWORD_FILE)")
	parent.PersistentFlags().BoolVarP(&yesFlag, "yes", "y", false,
		"Trust the controller's certificate authority on first use without asking (never replaces a changed one)")
	parent.PersistentFlags().BoolVar(&insecureFlag, "insecure", false,
		"Skip TLS certificate verification — sends the admin password unverified; last resort (or set ZITI_CTRL_INSECURE)")
	parent.PersistentFlags().StringVar(&controllerCAFlag, "controller-ca", "",
		"Path to PEM CA certificate to trust for the controller's TLS (or set ZITI_CTRL_CA)")

	// config print — no extra flags; no controller connection needed.
	printCmd := &cobra.Command{
		Use:   "print",
		Short: "Print the ziti-ssh-host.v1 config type field table and JSON schema",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigPrint()
		},
	}

	// config apply — idempotent create-or-update.
	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Idempotent install-or-update of the ziti-ssh-host.v1 config type on the controller",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := resolveControllerOptions(controllerFlag, usernameFlag, passwordFlag, passwordFileFlag, controllerCAFlag, insecureFlag, yesFlag)
			if err != nil {
				return err
			}
			return runConfigApply(opts)
		},
	}

	// config remove — delete by name if present.
	removeCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the ziti-ssh-host.v1 config type from the controller",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := resolveControllerOptions(controllerFlag, usernameFlag, passwordFlag, passwordFileFlag, controllerCAFlag, insecureFlag, yesFlag)
			if err != nil {
				return err
			}
			return runConfigRemove(opts)
		},
	}

	parent.AddCommand(printCmd)
	parent.AddCommand(applyCmd)
	parent.AddCommand(removeCmd)
	return parent
}

// controllerOptions are the resolved settings for a management API session.
type controllerOptions struct {
	ctrl, user, pass string
	caPath           string
	insecure, yes    bool
	caCacheDir       string
	confirm          trustPrompt
}

// resolveControllerOptions applies flag/env precedence, reads the password
// (flag, ZITI_CTRL_PASSWORD, --password-file / ZITI_CTRL_PASSWORD_FILE, or a
// hidden prompt), and validates the combination.
func resolveControllerOptions(ctrlFlag, userFlag, passFlag, passFileFlag, caFlag string, insecureFlag, yes bool) (controllerOptions, error) {
	o := controllerOptions{
		ctrl:     config.EnvOrFlag(ctrlFlag, "ZITI_CTRL_ADDRESS", ""),
		user:     config.EnvOrFlag(userFlag, "ZITI_CTRL_USERNAME", ""),
		caPath:   config.EnvOrFlag(caFlag, "ZITI_CTRL_CA", ""),
		insecure: insecureFlag || os.Getenv("ZITI_CTRL_INSECURE") == "true",
		yes:      yes,
	}
	if o.ctrl == "" {
		return o, fmt.Errorf("--controller (or ZITI_CTRL_ADDRESS) is required")
	}
	if o.user == "" {
		return o, fmt.Errorf("--username (or ZITI_CTRL_USERNAME) is required")
	}
	if o.insecure && o.caPath != "" {
		return o, fmt.Errorf("--insecure and --controller-ca are mutually exclusive")
	}

	interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
	passFile := config.EnvOrFlag(passFileFlag, "ZITI_CTRL_PASSWORD_FILE", "")
	switch {
	case passFlag != "":
		fmt.Fprintln(os.Stderr, "WARNING: --password is visible to other users in the process list and saved in shell history; prefer --password-file, ZITI_CTRL_PASSWORD, or the interactive prompt.")
		o.pass = passFlag
	case os.Getenv("ZITI_CTRL_PASSWORD") != "":
		o.pass = os.Getenv("ZITI_CTRL_PASSWORD")
	case passFile == "-":
		p, err := lineReader(os.Stdin)
		if err != nil {
			return o, fmt.Errorf("read password from stdin: %w", err)
		}
		o.pass = p
		interactive = false // stdin is consumed
	case passFile != "":
		b, err := os.ReadFile(passFile)
		if err != nil {
			return o, fmt.Errorf("read password file: %w", err)
		}
		o.pass = strings.TrimRight(strings.SplitN(string(b), "\n", 2)[0], "\r")
	case interactive:
		fmt.Fprintf(os.Stderr, "Password for %s: ", o.user)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return o, fmt.Errorf("read password: %w", err)
		}
		o.pass = string(b)
	}
	if o.pass == "" {
		return o, fmt.Errorf("a controller admin password is required (--password-file, ZITI_CTRL_PASSWORD, or run interactively)")
	}

	dir, err := defaultControllerCADir()
	if err != nil {
		return o, err
	}
	o.caCacheDir = dir
	if interactive {
		o.confirm = func(question string) bool {
			fmt.Fprint(os.Stderr, question)
			answer, _ := lineReader(os.Stdin)
			answer = strings.TrimSpace(answer)
			return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
		}
	}
	return o, nil
}

// resolveControllerHost strips any scheme prefix and appends the default port 443
// when no port is present. Accepts both "ctrl.example.com" and "https://ctrl.example.com".
func resolveControllerHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = u.Host // strips scheme, path, etc.
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return net.JoinHostPort(raw, "443")
}

// buildMgmtClient constructs a Ziti management API client and authenticates it.
// On success the returned *httptransport.Runtime has DefaultAuthentication set to
// the bearer token, so callers can pass nil as the auth info to each API call.
func buildMgmtClient(o controllerOptions) (*management.ZitiEdgeManagement, error) {
	host := resolveControllerHost(o.ctrl)
	user, pass := o.user, o.pass

	tlsCfg, err := controllerTLSConfig(controllerTrustOptions{
		host:     host,
		caPath:   o.caPath,
		insecure: o.insecure,
		yes:      o.yes,
		cacheDir: o.caCacheDir,
		confirm:  o.confirm,
		out:      os.Stderr,
	})
	if err != nil {
		return nil, err
	}

	transport := httptransport.New(host, "/edge/management/v1", []string{"https"})
	transport.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	mgmtClient := management.New(transport, strfmt.Default)

	authParams := authentication.NewAuthenticateParams().WithMethod("password")
	authParams.Auth = &rest_model.Authenticate{
		Username: rest_model.Username(user),
		Password: rest_model.Password(pass),
	}
	authOK, err := mgmtClient.Authentication.Authenticate(authParams)
	if err != nil {
		return nil, fmt.Errorf("authenticate to controller: %w", err)
	}
	if authOK.Payload == nil || authOK.Payload.Data == nil || authOK.Payload.Data.Token == nil {
		return nil, fmt.Errorf("authenticate: response missing session token")
	}

	transport.DefaultAuthentication = &rest_util.ZitiTokenAuth{Token: *authOK.Payload.Data.Token}
	return mgmtClient, nil
}

// schemaMap unmarshals the configTypeSchema constant into a map[string]interface{}
// suitable for the config type Schema field.
func schemaMap() (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(configTypeSchema), &m); err != nil {
		return nil, fmt.Errorf("unmarshal config type schema: %w", err)
	}
	return m, nil
}

func strPtr(s string) *string { return &s }

// runConfigPrint prints the human-readable field table and indented JSON schema.
func runConfigPrint() error {
	fmt.Print(configTypeFieldTable)

	var pretty map[string]interface{}
	if err := json.Unmarshal([]byte(configTypeSchema), &pretty); err != nil {
		return fmt.Errorf("format schema: %w", err)
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal schema: %w", err)
	}
	fmt.Printf("JSON schema:\n%s\n", out)
	return nil
}

// runConfigApply idempotently creates or updates the ziti-ssh-host.v1 config type.
func runConfigApply(o controllerOptions) error {
	mgmtClient, err := buildMgmtClient(o)
	if err != nil {
		return err
	}

	schema, err := schemaMap()
	if err != nil {
		return err
	}

	filter := fmt.Sprintf(`name="%s"`, configTypeName)
	listParams := config_client.NewListConfigTypesParams()
	listParams.Filter = &filter

	listResult, err := mgmtClient.Config.ListConfigTypes(listParams, nil)
	if err != nil {
		return fmt.Errorf("list config types: %w", err)
	}

	if len(listResult.Payload.Data) == 0 {
		// Not found — create it.
		createParams := config_client.NewCreateConfigTypeParams()
		createParams.ConfigType = &rest_model.ConfigTypeCreate{
			Name:   strPtr(configTypeName),
			Schema: schema,
		}
		if _, err := mgmtClient.Config.CreateConfigType(createParams, nil); err != nil {
			return fmt.Errorf("create config type: %w", err)
		}
		fmt.Printf("created config type %s\n", configTypeName)
		return nil
	}

	// Found — update it (full replacement PUT).
	existingID := *listResult.Payload.Data[0].ID

	updateParams := config_client.NewUpdateConfigTypeParams()
	updateParams.ID = existingID
	updateParams.ConfigType = &rest_model.ConfigTypeUpdate{
		Name:   strPtr(configTypeName),
		Schema: schema,
	}
	if _, err := mgmtClient.Config.UpdateConfigType(updateParams, nil); err != nil {
		return fmt.Errorf("update config type: %w", err)
	}
	fmt.Printf("updated config type %s (id: %s)\n", configTypeName, existingID)
	return nil
}

// runConfigRemove removes the ziti-ssh-host.v1 config type if it exists.
func runConfigRemove(o controllerOptions) error {
	mgmtClient, err := buildMgmtClient(o)
	if err != nil {
		return err
	}

	filter := fmt.Sprintf(`name="%s"`, configTypeName)
	listParams := config_client.NewListConfigTypesParams()
	listParams.Filter = &filter

	listResult, err := mgmtClient.Config.ListConfigTypes(listParams, nil)
	if err != nil {
		return fmt.Errorf("list config types: %w", err)
	}

	if len(listResult.Payload.Data) == 0 {
		fmt.Printf("config type %s not found — nothing to remove\n", configTypeName)
		return nil
	}

	existingID := *listResult.Payload.Data[0].ID

	deleteParams := config_client.NewDeleteConfigTypeParams()
	deleteParams.ID = existingID
	if _, err := mgmtClient.Config.DeleteConfigType(deleteParams, nil); err != nil {
		return fmt.Errorf("delete config type: %w", err)
	}
	fmt.Printf("removed config type %s\n", configTypeName)
	return nil
}
