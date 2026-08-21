package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// decodeTCP parses a serialized segment back into a TCP layer, the way the
// target's stack would.
func decodeTCP(t *testing.T, raw []byte) *layers.TCP {
	t.Helper()
	pkt := gopacket.NewPacket(raw, layers.LayerTypeTCP, gopacket.Default)
	layer := pkt.Layer(layers.LayerTypeTCP)
	if layer == nil {
		t.Fatalf("serialized bytes do not decode as TCP: % x", raw)
	}
	return layer.(*layers.TCP)
}

func TestBuildSYNIsASingleSYNSegment(t *testing.T) {
	src, dst := net.IPv4(192, 168, 1, 10), net.IPv4(192, 168, 1, 20)
	raw, err := buildSYN(src, dst, 40000, 443)
	if err != nil {
		t.Fatalf("buildSYN: %v", err)
	}
	tcp := decodeTCP(t, raw)

	if !tcp.SYN {
		t.Error("the SYN flag is the whole point")
	}
	// A half-open probe must not carry anything else that would complete or
	// abort the handshake on its own.
	if tcp.ACK || tcp.RST || tcp.FIN || tcp.PSH {
		t.Errorf("probe carries extra flags: ACK=%v RST=%v FIN=%v PSH=%v", tcp.ACK, tcp.RST, tcp.FIN, tcp.PSH)
	}
	if tcp.SrcPort != 40000 || tcp.DstPort != 443 {
		t.Errorf("ports = %d→%d, want 40000→443", tcp.SrcPort, tcp.DstPort)
	}
	if len(tcp.Payload) != 0 {
		t.Errorf("probe carries %d bytes of payload; it should carry none", len(tcp.Payload))
	}
}

func TestBuildSYNChecksumCoversThisAddressPair(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	raw, err := buildSYN(src, dst, 40000, 22)
	if err != nil {
		t.Fatalf("buildSYN: %v", err)
	}
	sum := decodeTCP(t, raw).Checksum
	if sum == 0 {
		t.Fatal("checksum was never computed — the target will drop the probe")
	}
	// The TCP checksum covers a pseudo-header of the addresses, so the same
	// segment to a different host must checksum differently.
	other, err := buildSYN(src, net.IPv4(10, 0, 0, 3), 40000, 22)
	if err != nil {
		t.Fatalf("buildSYN: %v", err)
	}
	if decodeTCP(t, other).Checksum == sum {
		t.Error("checksum ignored the destination address")
	}
}

func TestClassifyTCP(t *testing.T) {
	tests := []struct {
		name string
		tcp  layers.TCP
		want model.PortState
	}{
		{"syn-ack is open", layers.TCP{SYN: true, ACK: true}, model.StateOpen},
		{"rst is closed", layers.TCP{RST: true}, model.StateClosed},
		{"rst-ack is closed", layers.TCP{RST: true, ACK: true}, model.StateClosed},
		{"bare ack says nothing", layers.TCP{ACK: true}, ""},
		{"bare syn says nothing", layers.TCP{SYN: true}, ""},
		{"fin says nothing", layers.TCP{FIN: true, ACK: true}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tcp := tc.tcp
			if got := classifyTCP(&tcp); got != tc.want {
				t.Errorf("classifyTCP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBPFFilterMatchesOnlyOurReplies(t *testing.T) {
	got := bpfReplyFilter(net.IPv4(192, 168, 1, 20), 40000)
	want := "tcp and src host 192.168.1.20 and dst port 40000"
	if got != want {
		t.Errorf("filter = %q, want %q", got, want)
	}
}

func TestTrackerClassifiesSilenceAsFiltered(t *testing.T) {
	// The distinction the SYN engine buys us: silence is an observation here,
	// not an uninterpretable dial error.
	tr := newSYNTracker([]int{22, 80, 443})
	tr.record(22, model.StateOpen)
	tr.record(80, model.StateClosed)

	got := tr.services()
	if len(got) != 3 {
		t.Fatalf("services = %d, want one per requested port", len(got))
	}
	want := map[int]model.PortState{22: model.StateOpen, 80: model.StateClosed, 443: model.StateFiltered}
	for _, svc := range got {
		if svc.State != want[svc.Port] {
			t.Errorf("port %d = %q, want %q", svc.Port, svc.State, want[svc.Port])
		}
	}
}

func TestTrackerKeepsPortOrderAndNames(t *testing.T) {
	tr := newSYNTracker([]int{443, 22})
	got := tr.services()
	if got[0].Port != 443 || got[1].Port != 22 {
		t.Errorf("order = %d,%d — services should follow the requested port order", got[0].Port, got[1].Port)
	}
	if got[0].Name != "https" || got[1].Name != "ssh" {
		t.Errorf("names = %q,%q, want https,ssh", got[0].Name, got[1].Name)
	}
}

func TestTrackerIgnoresLaterContradictions(t *testing.T) {
	// A late RST after a SYN/ACK is the teardown, not a re-classification.
	tr := newSYNTracker([]int{22})
	tr.record(22, model.StateOpen)
	tr.record(22, model.StateClosed)
	if got := tr.services()[0].State; got != model.StateOpen {
		t.Errorf("state = %q, want the first answer (open) to stand", got)
	}
}

func TestTrackerPendingShrinksAsRepliesArrive(t *testing.T) {
	tr := newSYNTracker([]int{22, 80, 443})
	if len(tr.pending()) != 3 {
		t.Fatalf("pending = %v, want all three before any reply", tr.pending())
	}
	tr.record(80, model.StateClosed)
	pending := tr.pending()
	if len(pending) != 2 || pending[0] != 22 || pending[1] != 443 {
		t.Errorf("pending = %v, want the two unanswered ports in order", pending)
	}
}

func TestSelectEngineFallsBackLoudly(t *testing.T) {
	var notices []string
	choice := EngineChoice{
		Name:      EngineSYN,
		Available: func() error { return errors.New("operation not permitted") },
		Notice:    func(msg string) { notices = append(notices, msg) },
	}
	scanner, name, err := choice.Scanner()
	if err != nil {
		t.Fatalf("Scanner: %v", err)
	}
	if name != EngineConnect {
		t.Errorf("engine = %q, want the connect fallback", name)
	}
	if _, ok := scanner.(ConnectScanner); !ok {
		t.Errorf("scanner = %T, want ConnectScanner", scanner)
	}
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want exactly one — a silent fallback is the bug this guards", notices)
	}
	for _, want := range []string{"root", "connect", "sudo"} {
		if !strings.Contains(strings.ToLower(notices[0]), want) {
			t.Errorf("notice should mention %q: %q", want, notices[0])
		}
	}
}

func TestSelectEngineSYNWhenPrivileged(t *testing.T) {
	var notices []string
	scanner, name, err := EngineChoice{
		Name:      EngineSYN,
		Available: func() error { return nil },
		Notice:    func(msg string) { notices = append(notices, msg) },
	}.Scanner()
	if err != nil {
		t.Fatalf("Scanner: %v", err)
	}
	if name != EngineSYN {
		t.Errorf("engine = %q, want syn", name)
	}
	if _, ok := scanner.(*SYNScanner); !ok {
		t.Errorf("scanner = %T, want *SYNScanner", scanner)
	}
	if len(notices) != 0 {
		t.Errorf("nothing to report when the requested engine is what runs: %v", notices)
	}
}

func TestSelectEngineDefaultsToConnect(t *testing.T) {
	for _, name := range []string{"", EngineConnect} {
		scanner, resolved, err := EngineChoice{
			Name:      name,
			Available: func() error { t.Fatal("connect must never test for privileges"); return nil },
		}.Scanner()
		if err != nil {
			t.Fatalf("Scanner(%q): %v", name, err)
		}
		if resolved != EngineConnect {
			t.Errorf("engine = %q, want connect", resolved)
		}
		if _, ok := scanner.(ConnectScanner); !ok {
			t.Errorf("scanner = %T, want ConnectScanner", scanner)
		}
	}
}

func TestSelectEngineAutoPrefersSYNButSaysWhenItCannot(t *testing.T) {
	var notices []string
	_, name, err := EngineChoice{
		Name:      EngineAuto,
		Available: func() error { return errors.New("no raw sockets") },
		Notice:    func(msg string) { notices = append(notices, msg) },
	}.Scanner()
	if err != nil || name != EngineConnect {
		t.Fatalf("auto = %q (%v), want the connect fallback", name, err)
	}
	if len(notices) != 1 {
		t.Errorf("auto should still say which engine ran: %v", notices)
	}
}

func TestSelectEngineRejectsUnknownName(t *testing.T) {
	_, _, err := EngineChoice{Name: "nmap"}.Scanner()
	if err == nil {
		t.Fatal("want an error for an unknown engine")
	}
	if !strings.Contains(err.Error(), "connect") || !strings.Contains(err.Error(), "syn") {
		t.Errorf("error should list the valid engines: %v", err)
	}
}

func TestSYNScannerRejectsIPv6WithAdvice(t *testing.T) {
	_, err := (&SYNScanner{}).Scan(context.Background(), "2001:db8::1", []int{80})
	if err == nil {
		t.Fatal("want an error for IPv6")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("error should point at the engine that does work: %v", err)
	}
}

func TestSYNScannerRejectsNonAddress(t *testing.T) {
	if _, err := (&SYNScanner{}).Scan(context.Background(), "example.com", []int{80}); err == nil {
		t.Fatal("want an error for a name rather than an address")
	}
}

// TestSYNScanLive is the real thing, and it only runs as root — raw sockets and
// pcap both need privileges, and CI runners are unprivileged. It is skipped,
// not failed, everywhere else.
func TestSYNScanLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SYN scanning needs root; skipping the live test")
	}
	if err := Available(); err != nil {
		t.Skipf("raw sockets or pcap unavailable: %v", err)
	}

	open := openPort(t)
	closed := closedPort(t)
	svcs, err := (&SYNScanner{Timeout: time.Second}).
		Scan(context.Background(), "127.0.0.1", []int{open, closed})
	if err != nil {
		t.Fatalf("syn scan: %v", err)
	}
	byPort := map[int]model.PortState{}
	for _, s := range svcs {
		byPort[s.Port] = s.State
	}
	if byPort[open] != model.StateOpen {
		t.Errorf("open port %d = %q, want open", open, byPort[open])
	}
	if byPort[closed] != model.StateClosed {
		t.Errorf("closed port %d = %q, want closed", closed, byPort[closed])
	}
}
