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

package mfa

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadCode_EOFStops(t *testing.T) {
	// Previously an exhausted stdin made the prompt loop forever.
	var out bytes.Buffer
	if _, err := ReadCode(LineReader(strings.NewReader("")), &out, false); err == nil {
		t.Fatal("EOF accepted")
	}
}

func TestReadCode_RetriesEmptyThenGivesUp(t *testing.T) {
	var out bytes.Buffer
	code, err := ReadCode(LineReader(strings.NewReader("\n  \n123456\n")), &out, false)
	if err != nil || code != "123456" {
		t.Fatalf("got %q, %v", code, err)
	}
	if _, err := ReadCode(LineReader(strings.NewReader("\n\n\n\n")), &out, false); err == nil {
		t.Fatal("empty input accepted")
	}
	if code, err := ReadCode(LineReader(strings.NewReader("\n")), &out, true); err != nil || code != "" {
		t.Fatalf("allowEmpty: %q, %v", code, err)
	}
}

func TestListener_StopsAfterMaxAttempts(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	respond := func(code string) error { calls++; return errors.New("invalid") }
	Listener(LineReader(strings.NewReader("1\n2\n3\n4\n5\n")), &out)(nil, nil, respond)
	if calls != MaxAttempts {
		t.Fatalf("response called %d times, want %d", calls, MaxAttempts)
	}
	if !strings.Contains(out.String(), "too many failed attempts") {
		t.Errorf("output: %q", out.String())
	}
}

func TestListener_AcceptsValidCode(t *testing.T) {
	var out bytes.Buffer
	var got []string
	respond := func(code string) error {
		got = append(got, code)
		if code == "222222" {
			return nil
		}
		return errors.New("invalid")
	}
	Listener(LineReader(strings.NewReader("111111\n222222\n333333\n")), &out)(nil, nil, respond)
	if len(got) != 2 || got[1] != "222222" {
		t.Fatalf("codes sent: %v", got)
	}
}

func TestListener_NoTerminalExplains(t *testing.T) {
	var out bytes.Buffer
	Listener(nil, &out)(nil, nil, func(string) error { t.Fatal("response called"); return nil })
	if !strings.Contains(out.String(), "no terminal") {
		t.Errorf("output: %q", out.String())
	}
}
