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

package oidc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

// freePort returns a TCP port that is currently free on 127.0.0.1.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func closeAll(ls []net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}

func TestListenLoopback_BindsOnlyLoopback(t *testing.T) {
	ls, err := listenLoopback(freePort(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(ls)

	want := 1
	if ipv6LoopbackAvailable() {
		want = 2
	}
	if len(ls) != want {
		t.Fatalf("got %d listeners, want %d", len(ls), want)
	}
	for _, l := range ls {
		ip := l.Addr().(*net.TCPAddr).IP
		if !ip.IsLoopback() {
			t.Errorf("listener on non-loopback address %v", l.Addr())
		}
	}
}

func TestListenLoopback_RefusesWhenIPv4Taken(t *testing.T) {
	port := freePort(t)
	squatter, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()

	ls, err := listenLoopback(port)
	if err == nil {
		closeAll(ls)
		t.Fatal("listenLoopback succeeded although 127.0.0.1 port is held by another listener")
	}
	if !strings.Contains(err.Error(), "refusing to continue") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListenLoopback_RefusesWhenIPv6Taken(t *testing.T) {
	if !ipv6LoopbackAvailable() {
		t.Skip("no IPv6 loopback on this host")
	}
	port := freePort(t)
	squatter, err := net.Listen("tcp6", "[::1]:"+port)
	if err != nil {
		t.Skipf("cannot bind [::1]:%s for the test: %v", port, err)
	}
	defer squatter.Close()

	ls, err := listenLoopback(port)
	if err == nil {
		closeAll(ls)
		t.Fatal("listenLoopback succeeded although ::1 port is held by another listener")
	}
	// The IPv4 listener must have been released on failure.
	l, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("127.0.0.1:%s not released after failure: %v", port, err)
	}
	l.Close()
}

func TestOpenBrowser_PrintsURLAndSurvivesFailure(t *testing.T) {
	var out bytes.Buffer
	const url = "http://localhost:63275/login"
	openBrowser(url, &out, func(string, ...string) error { return errors.New("no display") })

	got := out.String()
	urlAt := strings.Index(got, url)
	failAt := strings.Index(got, "open the URL above manually")
	if urlAt < 0 || failAt < 0 || urlAt > failAt {
		t.Fatalf("URL must be printed before the failure notice; output:\n%s", got)
	}
}

func TestOpenBrowser_Success(t *testing.T) {
	var out bytes.Buffer
	var called string
	openBrowser("http://localhost:1/login", &out, func(name string, _ ...string) error { called = name; return nil })
	if called == "" {
		t.Error("browser launcher not called")
	}
	if strings.Contains(out.String(), "manually") {
		t.Errorf("failure notice printed on success:\n%s", out.String())
	}
}

func TestOffer_DoesNotBlock(t *testing.T) {
	ch := make(chan int, 1)
	if !offer(ch, 1) {
		t.Fatal("first value not delivered")
	}
	if offer(ch, 2) {
		t.Fatal("second value delivered into a full channel")
	}
	if v := <-ch; v != 1 {
		t.Fatalf("got %d, want the first value", v)
	}
}

func TestRunFlow_RefusesBeforeContactingIssuerWhenPortTaken(t *testing.T) {
	port := freePort(t)
	squatter, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()

	// example.invalid can never resolve (RFC 2606). If the flow contacted the
	// issuer first, the error would be about discovery/DNS instead.
	_, err = runFlow(context.Background(), FlowParams{
		Issuer:       "https://example.invalid",
		ClientID:     "test",
		CallbackPort: port,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to continue") {
		t.Fatalf("want callback-port refusal before issuer discovery, got: %v", err)
	}
}

func TestRunFlow_ReleasesPortWhenIssuerFails(t *testing.T) {
	port := freePort(t)
	_, err := runFlow(context.Background(), FlowParams{
		Issuer:       "https://example.invalid",
		ClientID:     "test",
		CallbackPort: port,
	})
	if err == nil || strings.Contains(err.Error(), "refusing to continue") {
		t.Fatalf("want an issuer discovery error, got: %v", err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("callback port not released after a failed flow: %v", err)
	}
	l.Close()
}
