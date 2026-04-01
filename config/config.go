// Package config provides shared configuration helpers for resolving values
// from CLI flags, environment variables, and built-in defaults.
package config

import "os"

// EnvOrFlag resolves a configuration value using the following precedence:
//  1. flagVal — the parsed CLI flag value (highest priority)
//  2. os.Getenv(envKey) — environment variable
//  3. defaultVal — built-in default (lowest priority)
func EnvOrFlag(flagVal, envKey, defaultVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return defaultVal
}
