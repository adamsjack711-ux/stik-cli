package probe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

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

// openListener returns a live 127.0.0.1 listener and its port.
func openListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port on 127.0.0.1 that is guaranteed closed (a listener
// was opened to reserve it, then closed), so a probe gets a refusal not a hang.
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

func TestDiscoverFindsHostWithOpenPort(t *testing.T) {
	_, port := openListener(t)
	hosts, stats, err := Discover(context.Background(), scopeOf(t, "127.0.0.1/32"),
		Options{Ports: []int{port}, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(hosts) != 1 || hosts[0].IP != "127.0.0.1" || !hosts[0].Up {
		t.Fatalf("want one up host 127.0.0.1, got %+v", hosts)
	}
	if hosts[0].DiscoveredBy != "tcp-ping" {
		t.Errorf("DiscoveredBy = %q, want tcp-ping", hosts[0].DiscoveredBy)
	}
	if stats.Up != 1 || stats.Candidates != 1 {
		t.Errorf("stats = %+v, want 1 candidate / 1 up", stats)
	}
}

// A refused connection (RST) still proves the host is up — the whole point of
// TCP-ping working against hosts with no open ports.
func TestRefusedConnectionCountsAsUp(t *testing.T) {
	hosts, _, err := Discover(context.Background(), scopeOf(t, "127.0.0.1/32"),
		Options{Ports: []int{closedPort(t)}, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(hosts) != 1 || !hosts[0].Up {
		t.Fatalf("loopback with a refused port should be up, got %+v", hosts)
	}
}

func TestDiscoverEmptyScopeErrors(t *testing.T) {
	if _, _, err := Discover(context.Background(), &scope.Set{}, Options{}); err == nil {
		t.Fatal("empty scope must error, never probe")
	}
}

// The gate: ping must refuse an address the scope does not contain, even if
// called directly with a live loopback target.
func TestPingHonorsScope(t *testing.T) {
	_, port := openListener(t)
	p := &pinger{ports: []int{port}, timeout: 500 * time.Millisecond, scope: scopeOf(t, "10.0.0.0/24")}
	if _, up := p.ping(context.Background(), net.ParseIP("127.0.0.1")); up {
		t.Fatal("ping probed an out-of-scope address")
	}
}

func TestEnumerateSkipsNetworkAndBroadcast(t *testing.T) {
	// A /30 has 4 addresses; net + broadcast are skipped, leaving 2 usable.
	ips, err := enumerate(scopeOf(t, "192.168.5.0/30"), DefaultMaxHosts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	got := ipset(ips)
	if len(ips) != 2 {
		t.Fatalf("/30 should enumerate 2 hosts, got %d (%v)", len(ips), ips)
	}
	if got["192.168.5.0"] || got["192.168.5.3"] {
		t.Error("network (.0) and broadcast (.3) must be excluded")
	}
	if !got["192.168.5.1"] || !got["192.168.5.2"] {
		t.Error("usable hosts .1 and .2 must be included")
	}
}

func TestEnumerateSingleHost(t *testing.T) {
	ips, err := enumerate(scopeOf(t, "10.0.0.5/32"), DefaultMaxHosts)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "10.0.0.5" {
		t.Fatalf("/32 should enumerate exactly its host, got %v", ips)
	}
}

func TestEnumerateCapExceeded(t *testing.T) {
	if _, err := enumerate(scopeOf(t, "10.0.0.0/24"), 10); err == nil {
		t.Fatal("enumeration past the cap must error, not sweep")
	}
}

func ipset(ips []net.IP) map[string]bool {
	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		m[ip.String()] = true
	}
	return m
}

// Naming a target narrows, never widens: a candidate that is up but not in the
// authorized scope must not be probed.
func TestDiscoverInNarrowsToAuth(t *testing.T) {
	_, port := openListener(t)
	auth := scopeOf(t, "10.0.0.0/24")  // loopback NOT authorized
	cand := scopeOf(t, "127.0.0.1/32") // but named as a target
	hosts, _, err := DiscoverIn(context.Background(), auth, cand,
		Options{Ports: []int{port}, Timeout: 400 * time.Millisecond})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("target outside authorized scope must not be probed, got %+v", hosts)
	}
}

func TestIPv6RangeSaysEnumerationIsImpossible(t *testing.T) {
	// Raising --max-hosts does not make a /64 sweepable, so repeating that advice
	// would send someone down a dead end.
	sc := scopeOf(t, "2001:db8::/64")
	_, err := enumerate(sc, 128)
	if err == nil {
		t.Fatal("want an error for a /64")
	}
	if !strings.Contains(err.Error(), "cannot be enumerated") {
		t.Errorf("error should explain why, got: %v", err)
	}
	if strings.Contains(err.Error(), "--max-hosts") {
		t.Errorf("error should not suggest a flag that cannot help: %v", err)
	}
}

func TestExplicitIPv6AddressesAreStillProbed(t *testing.T) {
	// Listing addresses is the supported IPv6 path, so it has to work.
	sc := scopeOf(t, "2001:db8::20/128\n2001:db8::21/128")
	got, err := enumerate(sc, 128)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("enumerated %d addresses, want both", len(got))
	}
	if got[0].String() != "2001:db8::20" || got[1].String() != "2001:db8::21" {
		t.Errorf("got %v", got)
	}
}
