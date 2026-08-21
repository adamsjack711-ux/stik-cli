package portscan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

func scopeOf(t *testing.T, text string) *scope.Set {
	t.Helper()
	s, err := scope.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("scope parse: %v", err)
	}
	return s
}

func openPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestConnectScannerClassifiesState(t *testing.T) {
	open := openPort(t)
	closed := closedPort(t)
	svcs, err := ConnectScanner{Timeout: 500 * time.Millisecond}.
		Scan(context.Background(), "127.0.0.1", []int{open, closed})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byPort := map[int]model.PortState{}
	for _, s := range svcs {
		byPort[s.Port] = s.State
	}
	if byPort[open] != model.StateOpen {
		t.Errorf("open port %d: state = %q, want open", open, byPort[open])
	}
	if byPort[closed] != model.StateClosed {
		t.Errorf("closed port %d: state = %q, want closed", closed, byPort[closed])
	}
}

func TestScanHostsFillsOpenServicesOnly(t *testing.T) {
	open := openPort(t)
	closed := closedPort(t)
	hosts := []model.Host{{IP: "127.0.0.1", Up: true}}
	got, stats := ScanHosts(context.Background(), scopeOf(t, "127.0.0.1/32"), hosts,
		Options{Ports: []int{open, closed}, Timeout: 500 * time.Millisecond})

	if len(got) != 1 || len(got[0].Services) != 1 {
		t.Fatalf("want exactly the one open service, got %+v", got[0].Services)
	}
	if got[0].Services[0].Port != open || got[0].Services[0].State != model.StateOpen {
		t.Errorf("kept service = %+v, want open port %d", got[0].Services[0], open)
	}
	if stats.Open != 1 || stats.Hosts != 1 {
		t.Errorf("stats = %+v, want 1 host / 1 open", stats)
	}
}

// The gate: a host outside the scope is never scanned, even if it's live.
func TestScanHostsHonorsScope(t *testing.T) {
	open := openPort(t)
	hosts := []model.Host{{IP: "127.0.0.1", Up: true}}
	got, stats := ScanHosts(context.Background(), scopeOf(t, "10.0.0.0/24"), hosts,
		Options{Ports: []int{open}, Timeout: 500 * time.Millisecond})
	if len(got[0].Services) != 0 {
		t.Fatal("out-of-scope host must not be scanned")
	}
	if stats.Open != 0 {
		t.Errorf("stats.Open = %d, want 0", stats.Open)
	}
}

func TestServiceNameLabels(t *testing.T) {
	if ServiceName(443) != "https" || ServiceName(22) != "ssh" {
		t.Error("well-known ports should get names")
	}
	if ServiceName(64999) != "" {
		t.Error("unknown port should return empty name")
	}
}

func TestScanResultsSortedByPort(t *testing.T) {
	p1, p2 := openPort(t), openPort(t)
	lo, hi := p1, p2
	if lo > hi {
		lo, hi = hi, lo
	}
	hosts := []model.Host{{IP: "127.0.0.1", Up: true}}
	got, _ := ScanHosts(context.Background(), scopeOf(t, "127.0.0.1/32"), hosts,
		Options{Ports: []int{hi, lo}, Timeout: 500 * time.Millisecond})
	if len(got[0].Services) != 2 || got[0].Services[0].Port != lo {
		t.Fatalf("services should be sorted ascending by port, got %+v", got[0].Services)
	}
}
