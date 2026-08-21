package portscan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// echoUDP answers every datagram, standing in for a UDP service that talks.
func echoUDP(t *testing.T, reply []byte) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			out := reply
			if out == nil {
				out = buf[:n]
			}
			_, _ = conn.WriteTo(out, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// silentUDP holds a port open and never answers — the case UDP cannot resolve.
func silentUDP(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func closedUDP(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

func statesByPort(svcs []model.Service) map[int]model.PortState {
	out := map[int]model.PortState{}
	for _, s := range svcs {
		out[s.Port] = s.State
	}
	return out
}

func TestUDPScanClassifiesTheThreeStates(t *testing.T) {
	answering := echoUDP(t, []byte("pong"))
	silent := silentUDP(t)
	closed := closedUDP(t)

	svcs, err := (&UDPScanner{Timeout: 400 * time.Millisecond}).
		Scan(context.Background(), "127.0.0.1", []int{answering, silent, closed})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	states := statesByPort(svcs)

	if states[answering] != model.StateOpen {
		t.Errorf("a service that replied = %q, want open", states[answering])
	}
	// This is the honest answer, and the reason UDP needs a third state: a
	// service with nothing to say is indistinguishable from a dropped packet.
	if states[silent] != model.StateOpenFiltered {
		t.Errorf("a silent listener = %q, want open|filtered", states[silent])
	}
	if states[closed] != model.StateClosed {
		t.Errorf("a closed port = %q, want closed (ICMP unreachable)", states[closed])
	}
}

func TestUDPScanKeepsProtocolAndName(t *testing.T) {
	port := echoUDP(t, []byte("pong"))
	svcs, err := (&UDPScanner{Timeout: 300 * time.Millisecond}).
		Scan(context.Background(), "127.0.0.1", []int{port})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if svcs[0].Proto != "udp" {
		t.Errorf("proto = %q, want udp — the rules key on it", svcs[0].Proto)
	}
	if svcs[0].Banner != "pong" {
		t.Errorf("banner = %q, want the reply", svcs[0].Banner)
	}
}

func TestUDPScanNamesWellKnownPorts(t *testing.T) {
	if UDPServiceName(161) != "snmp" || UDPServiceName(1900) != "ssdp" {
		t.Error("well-known UDP ports should be named")
	}
	if UDPServiceName(64999) != "" {
		t.Error("unknown ports should have no name")
	}
}

func TestUDPScanSortsAndRejectsHostnames(t *testing.T) {
	a, b := silentUDP(t), silentUDP(t)
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	svcs, err := (&UDPScanner{Timeout: 200 * time.Millisecond}).
		Scan(context.Background(), "127.0.0.1", []int{hi, lo})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if svcs[0].Port != lo {
		t.Errorf("results should be sorted by port, got %d first", svcs[0].Port)
	}

	if _, err := (&UDPScanner{}).Scan(context.Background(), "example.com", []int{53}); err == nil {
		t.Error("want an error for a name rather than an address")
	}
}

func TestUDPProbesAreProtocolShaped(t *testing.T) {
	// An empty datagram gets nothing back from a real resolver or NTP server, so
	// a scanner that sends one reports every live service as silent.
	if len(udpProbe(53)) < 12 || string(udpProbe(53)[13:20]) != "version" {
		t.Errorf("port 53 should get a DNS query, got % x", udpProbe(53))
	}
	if udpProbe(123)[0] != 0x1b || len(udpProbe(123)) != 48 {
		t.Errorf("port 123 should get a 48-byte NTP client packet, got %d bytes", len(udpProbe(123)))
	}
	if !strings.HasPrefix(string(udpProbe(1900)), "M-SEARCH * HTTP/1.1") {
		t.Error("port 1900 should get an SSDP M-SEARCH")
	}
	if !strings.Contains(string(udpProbe(161)), "public") {
		t.Error("port 161 should get an SNMP get with the default community")
	}
	// Anything we have no protocol for still gets a byte, so a closed port can
	// answer with ICMP unreachable.
	if len(udpProbe(64999)) == 0 {
		t.Error("unknown ports still need a payload")
	}
}

func TestDHCPPortsGetNoLeaseRequest(t *testing.T) {
	// Sending a real DHCPDISCOVER would take an address off the network. That is
	// a change, not an observation, and this tool does not make changes.
	for _, port := range []int{67, 68} {
		if len(udpProbe(port)) != 1 {
			t.Errorf("port %d should get the generic probe, not a DHCP payload", port)
		}
	}
}

func TestSanitizeUDPReply(t *testing.T) {
	if got := sanitizeUDP([]byte("hello\x00world")); got != "helloworld" {
		t.Errorf("printable reply = %q", got)
	}
	// Binary replies are common; a length is more useful than mojibake.
	if got := sanitizeUDP([]byte{0x00, 0x01, 0x02, 0x03, 0xff}); got != "5 bytes" {
		t.Errorf("binary reply = %q, want a length", got)
	}
	if got := sanitizeUDP(nil); got != "" {
		t.Errorf("empty reply = %q", got)
	}
}

func TestScanHostsRunsTheUDPPass(t *testing.T) {
	answering := echoUDP(t, []byte("pong"))
	tcpOpen := openPort(t)

	hosts := []model.Host{{IP: "127.0.0.1", Up: true}}
	got, stats := ScanHosts(context.Background(), scopeOf(t, "127.0.0.1/32"), hosts, Options{
		Ports:    []int{tcpOpen},
		UDPPorts: []int{answering},
		Timeout:  500 * time.Millisecond,
	})

	var sawTCP, sawUDP bool
	for _, svc := range got[0].Services {
		switch svc.Proto {
		case "tcp":
			sawTCP = svc.Port == tcpOpen && svc.State == model.StateOpen
		case "udp":
			sawUDP = svc.Port == answering && svc.State == model.StateOpen
		}
	}
	if !sawTCP || !sawUDP {
		t.Fatalf("want both passes represented, got %+v", got[0].Services)
	}
	if stats.Open != 2 {
		t.Errorf("stats.Open = %d, want both open services counted", stats.Open)
	}
}

func TestUDPPassHonorsScope(t *testing.T) {
	answering := echoUDP(t, []byte("pong"))
	hosts := []model.Host{{IP: "127.0.0.1", Up: true}}
	got, _ := ScanHosts(context.Background(), scopeOf(t, "10.0.0.0/24"), hosts, Options{
		Ports:    []int{},
		UDPPorts: []int{answering},
		Timeout:  300 * time.Millisecond,
	})
	if len(got[0].Services) != 0 {
		t.Errorf("out-of-scope host was probed over UDP: %+v", got[0].Services)
	}
}
