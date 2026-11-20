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

// Package mfa prompts for Ziti MFA TOTP codes during authentication.
//
// The SDK emits ziti.EventMfaTotpCode from Authenticate when an identity has
// MFA enrolled; without a listener nothing answers and authentication cannot
// complete. Codes are read without echo when the input is a terminal.
package mfa

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti"
	"golang.org/x/term"
)

// MaxAttempts is the number of codes accepted before giving up.
const MaxAttempts = 3

// ReadFunc reads one code (without the prompt).
type ReadFunc func() (string, error)

// NewReader returns a ReadFunc for f: hidden input when f is a terminal,
// otherwise one line at a time.
func NewReader(f *os.File) ReadFunc {
	fd := int(f.Fd())
	if term.IsTerminal(fd) {
		return func() (string, error) {
			b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}
	}
	return LineReader(f)
}

// LineReader returns a ReadFunc reading newline-terminated lines from r.
// io.EOF is returned once r is exhausted.
func LineReader(r io.Reader) ReadFunc {
	br := bufio.NewReader(r)
	return func() (string, error) {
		line, err := br.ReadString('\n')
		if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
			return "", err
		}
		return line, nil
	}
}

// ReadCode prompts on out and reads a code. Empty input is re-prompted (up to
// MaxAttempts times) unless allowEmpty. A read error (e.g. EOF) is returned
// instead of looping.
func ReadCode(read ReadFunc, out io.Writer, allowEmpty bool) (string, error) {
	for i := 0; i < MaxAttempts; i++ {
		fmt.Fprint(out, "MFA TOTP code: ")
		code, err := read()
		if err != nil {
			fmt.Fprintln(out)
			return "", fmt.Errorf("read MFA code: %w", err)
		}
		code = strings.TrimSpace(code)
		if code != "" || allowEmpty {
			return code, nil
		}
	}
	return "", errors.New("no MFA code entered")
}

// Listener returns an EventMfaTotpCode listener that reads codes with read
// and reports on out. It gives up after MaxAttempts rejected codes or on a
// read error. If read is nil (no terminal available) it only explains why
// authentication cannot complete.
func Listener(read ReadFunc, out io.Writer) func(ziti.Context, *rest_model.AuthQueryDetail, ziti.MfaCodeResponse) {
	return func(_ ziti.Context, _ *rest_model.AuthQueryDetail, response ziti.MfaCodeResponse) {
		if read == nil {
			fmt.Fprintln(out, "This identity requires an MFA TOTP code, but no terminal is available to ask for it.")
			return
		}
		fmt.Fprintln(out, "MFA TOTP required to fully authenticate.")
		for i := 0; i < MaxAttempts; i++ {
			code, err := ReadCode(read, out, false)
			if err != nil {
				fmt.Fprintln(out, "MFA aborted:", err)
				return
			}
			if err := response(code); err != nil {
				fmt.Fprintln(out, "error verifying MFA TOTP:", err)
				continue
			}
			return
		}
		fmt.Fprintln(out, "MFA aborted: too many failed attempts")
	}
}

// RegisterTTY registers a listener that prompts and reads codes on the
// controlling terminal (/dev/tty), as ssh(1) does for passwords, so piped
// stdin (or the SSH stream in ProxyCommand mode) is never consumed. Without a
// terminal the listener explains why authentication cannot complete. The
// returned function closes the terminal.
func RegisterTTY(ctx ziti.Context) (closeFn func()) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		ctx.Events().AddMfaTotpCodeListener(Listener(nil, os.Stderr))
		return func() {}
	}
	read := func() (string, error) {
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(b), err
	}
	if !term.IsTerminal(int(tty.Fd())) {
		read = LineReader(tty)
	}
	ctx.Events().AddMfaTotpCodeListener(Listener(read, tty))
	return func() { _ = tty.Close() }
}
