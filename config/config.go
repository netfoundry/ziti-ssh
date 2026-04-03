// Package config provides shared configuration helpers for resolving values
// from CLI flags, environment variables, and built-in defaults.
package config

import (
	"fmt"
	"os"
	"time"
)

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

// ZitiTimeoutErr is the user-facing error message returned when a Ziti
// operation does not complete within the configured timeout.
func ZitiTimeoutErr(op string, timeout time.Duration) error {
	return fmt.Errorf("timed out after %s waiting for Ziti network during %s — check that the controller is reachable and the identity is valid", timeout, op)
}

// RunWithTimeout executes fn in a goroutine and returns its error. If fn does
// not return within timeout, ZitiTimeoutErr is returned instead.
//
// Use this to wrap blocking Ziti SDK calls that do not accept a context
// (e.g. Authenticate, Listen, ListenWithOptions).
func RunWithTimeout(timeout time.Duration, op string, fn func() error) error {
	ch := make(chan error, 1)
	go func() {
		ch <- fn()
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		return ZitiTimeoutErr(op, timeout)
	}
}
