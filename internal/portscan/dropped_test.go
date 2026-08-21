package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// A filtered port is the state both engines find hardest to be honest about,
// and until now nothing exercised it against a live host: the black-hole test
// aims at an address that routes nowhere, which is a different situation from a
// host that answers on one port and silently drops SYNs on another.
//
// The obvious way to arrange that is a firewall rule, which means mutating the
// firewall of whatever machine runs the tests and restoring it correctly
// afterwards — including when the test panics. This does it without touching
// any system state: a listening socket with a full accept queue drops further
// SYNs on the floor. No SYN/ACK, no RST, and the host is unquestionably alive.
//
// The harness verifies its own premise before asserting anything. Queue
// behaviour differs between kernels, so if this machine refuses or accepts
// instead of dropping, the test skips and says so rather than passing on a
// scenario it never actually created.

// droppedSYNPort returns a port on a live host whose SYNs go nowhere, plus the
// connections holding its accept queue full.
func droppedSYNPort(t *testing.T) int {
	t.Helper()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("raw listen socket unavailable: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })

	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("bind: %v", err)
	}
	// Backlog 1: the smallest queue the kernel will give us. Everything past it
	// is dropped rather than refused.
	if err := syscall.Listen(fd, 1); err != nil {
		t.Skipf("listen: %v", err)
	}

	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Skipf("getsockname: %v", err)
	}
	addr, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Skip("unexpected socket address type")
	}
	port := addr.Port

	// Fill the queue. Nothing ever calls accept, so these sit there.
	target := net.JoinHostPort("127.0.0.1", itoa(port))
	for i := 0; i < 24; i++ {
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err != nil {
			break // the queue is full; further SYNs are being dropped
		}
		t.Cleanup(func() { conn.Close() })
	}

	// Verify the premise: a fresh connection must now hang, not be refused.
	probe, err := net.DialTimeout("tcp", target, 600*time.Millisecond)
	if err == nil {
		probe.Close()
		t.Skip("this kernel still accepts past a full backlog; no dropped-SYN scenario to test")
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		t.Skip("this kernel refuses past a full backlog instead of dropping; no dropped-SYN scenario to test")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Skipf("expected a timeout from a saturated backlog, got %v", err)
	}
	return port
}

// TestConnectScannerReportsFilteredOnDroppedSYN is the unprivileged half: it
// runs everywhere, including CI, and pins that a live host silently dropping
// SYNs reads as filtered rather than closed.
func TestConnectScannerReportsFilteredOnDroppedSYN(t *testing.T) {
	port := droppedSYNPort(t)

	svcs, err := ConnectScanner{Timeout: 700 * time.Millisecond}.
		Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(svcs) != 1 {
		t.Fatalf("services = %+v", svcs)
	}
	if svcs[0].State != model.StateFiltered {
		t.Errorf("state = %q, want filtered — a dropped SYN is not a refusal", svcs[0].State)
	}
}

// TestSYNScanFilteredOnDroppedSYN is the same scenario through the half-open
// engine, where filtered is a genuine observation rather than an uninterpreted
// dial error. Root-only, like every live SYN test.
func TestSYNScanFilteredOnDroppedSYN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SYN scanning needs root; skipping")
	}
	if err := Available(); err != nil {
		t.Skipf("raw sockets or pcap unavailable: %v", err)
	}

	port := droppedSYNPort(t)
	open := openPort(t)
	closed := closedPort(t)

	svcs, err := (&SYNScanner{Timeout: 800 * time.Millisecond, Retries: 1}).
		Scan(context.Background(), "127.0.0.1", []int{open, closed, port})
	if err != nil {
		t.Fatalf("syn scan: %v", err)
	}
	states := map[int]model.PortState{}
	for _, s := range svcs {
		states[s.Port] = s.State
	}

	// All three states, on one live host, in one scan — which is the thing the
	// black-hole test could never show.
	if states[open] != model.StateOpen {
		t.Errorf("open port = %q, want open", states[open])
	}
	if states[closed] != model.StateClosed {
		t.Errorf("closed port = %q, want closed", states[closed])
	}
	if states[port] != model.StateFiltered {
		t.Errorf("dropped-SYN port = %q, want filtered", states[port])
	}
}
