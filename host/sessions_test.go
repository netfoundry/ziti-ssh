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

package host

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestEnsureUserForService_CrossServiceConflictRejected(t *testing.T) {
	ops := newFakeOps()
	m := testManager(t, t.TempDir(), ops, false)
	ops2 := IdentityPermissions{Groups: []string{"adm", "sudo"}}
	db := IdentityPermissions{Groups: []string{"mysql"}}

	if err := m.EnsureUserForService("alice", "alice", "ssh-ops", ops2); err != nil {
		t.Fatal(err)
	}
	// Different service, different permissions, while ssh-ops is open: reject.
	err := m.EnsureUserForService("alice", "alice", "ssh-db", db)
	if !errors.Is(err, ErrPermissionConflict) {
		t.Fatalf("want ErrPermissionConflict, got %v", err)
	}
	if ops.called("groups:alice:mysql") {
		t.Error("conflicting connection changed the account's groups")
	}
	// Different service, same permissions (order/duplicates ignored): allowed.
	if err := m.EnsureUserForService("alice", "alice", "ssh-other", IdentityPermissions{Groups: []string{"sudo", "adm", "sudo"}}); err != nil {
		t.Fatalf("same permissions via another service: %v", err)
	}
	// Same service as the latest admission with changed config: applied.
	if err := m.EnsureUserForService("alice", "alice", "ssh-other", IdentityPermissions{Groups: []string{"adm"}}); err != nil {
		t.Fatalf("same service, new config: %v", err)
	}
	// Once every session is closed, another service is fine.
	for i := 0; i < 3; i++ {
		if err := m.ReleaseUser("alice"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.EnsureUserForService("alice", "alice", "ssh-db", db); err != nil {
		t.Fatalf("after all sessions closed: %v", err)
	}
}

func TestProxyLimited_ClosesExcessConnections(t *testing.T) {
	// Target that holds every connection open.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ProxyLimited(front, target.Addr().String(), nil, nil, 1)
	defer front.Close()

	first, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Wait until the first connection is proxied (holds the only slot).
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(held)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first connection never reached the target")
		}
		time.Sleep(10 * time.Millisecond)
	}

	second, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("second connection not closed by the limit: %v", err)
	}
}
