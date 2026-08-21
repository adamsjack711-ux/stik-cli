package portscan

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// The SYN engine sends a bare SYN and reads what comes back, never completing
// the handshake. It is faster than a connect scan and leaves no accepted
// connection in the target's application logs, but it needs raw-socket
// privileges — root, or CAP_NET_RAW.
//
// Sending and receiving use different mechanisms on purpose. The kernel builds
// the IP header for us on an "ip4:tcp" socket, which spares us ARP and L2
// entirely; but BSD-derived kernels (macOS included) never deliver TCP to a raw
// socket, so replies are read through pcap with a tight BPF filter instead.
//
// One consequence worth stating: because the reply arrives at a port no socket
// is bound to, the kernel answers a SYN/ACK with its own RST. That is how the
// half-open connection gets torn down, and it is what every SYN scanner does.

const (
	synSnapLen = 128 // an IP+TCP header and nothing more
	synWindow  = 1024
)

// SYNScanner is the privileged half-open engine.
type SYNScanner struct {
	Timeout time.Duration // how long to wait for replies after the last SYN
	Iface   string        // capture interface; auto-detected per target when empty
	Retries int           // extra SYNs for ports that stayed silent; default 1
	Rate    time.Duration // pause between SYNs; 0 sends as fast as the socket takes them
}

// Available reports whether this process can run a SYN scan at all, and why not
// when it can't. It is the check behind the fallback to the connect engine.
func Available() error {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("raw sockets unavailable: %w", err)
	}
	conn.Close()
	if _, err := pcap.FindAllDevs(); err != nil {
		return fmt.Errorf("packet capture unavailable: %w", err)
	}
	return nil
}

// Scan sends one SYN per port and classifies what comes back: SYN/ACK is open,
// RST is closed, and silence — after the retries — is filtered. Unlike the
// connect engine, "filtered" here is a genuine observation of no reply rather
// than a dial error we couldn't interpret.
func (s *SYNScanner) Scan(ctx context.Context, host string, ports []int) ([]model.Service, error) {
	dst := net.ParseIP(host)
	if dst == nil {
		return nil, fmt.Errorf("syn scan: %q is not an IP address", host)
	}
	v6 := dst.To4() == nil
	if !v6 {
		dst = dst.To4()
	}

	src, iface, err := routeTo(dst, s.Iface)
	if err != nil {
		return nil, err
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = 700 * time.Millisecond
	}
	retries := s.Retries
	if retries == 0 {
		retries = 1
	}

	handle, err := pcap.OpenLive(iface, synSnapLen, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("syn scan: capturing on %s: %w", iface, err)
	}
	defer handle.Close()

	sport := ephemeralPort()
	if err := handle.SetBPFFilter(bpfReplyFilter(dst, sport, v6)); err != nil {
		return nil, fmt.Errorf("syn scan: %w", err)
	}

	sender, err := net.ListenPacket(rawNetwork(v6), src.String())
	if err != nil {
		return nil, fmt.Errorf("syn scan: raw socket: %w", err)
	}
	defer sender.Close()

	tracker := newSYNTracker(ports)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readReplies(handle, tracker, done)
	}()

	for attempt := 0; attempt <= retries; attempt++ {
		pending := tracker.pending()
		if len(pending) == 0 {
			break
		}
		for _, port := range pending {
			if err := ctx.Err(); err != nil {
				close(done)
				handle.Close()
				wg.Wait()
				return tracker.services(), err
			}
			if err := sendSYN(sender, src, dst, sport, uint16(port), v6); err != nil {
				tracker.fail(port, err)
			}
			if s.Rate > 0 {
				time.Sleep(s.Rate)
			}
		}
		// Wait for the reply window — but stop the moment every port has
		// answered. Sitting out the full timeout after the last reply is pure
		// dead time, and it is most of a scan's wall clock on a live host.
		select {
		case <-time.After(timeout):
		case <-tracker.answered():
		case <-ctx.Done():
		}
	}

	close(done)
	handle.Close() // unblocks the reader
	wg.Wait()
	return tracker.services(), nil
}

// readReplies decodes captured packets until done is closed or the handle dies.
func readReplies(handle *pcap.Handle, tracker *synTracker, done <-chan struct{}) {
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()
	for {
		select {
		case <-done:
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			layer := pkt.Layer(layers.LayerTypeTCP)
			if layer == nil {
				continue
			}
			tcp, _ := layer.(*layers.TCP)
			tracker.record(int(tcp.SrcPort), classifyTCP(tcp))
		}
	}
}

// classifyTCP reads a port's state off the reply's flags. A SYN/ACK means the
// port accepted; a RST means it refused. Anything else tells us nothing.
func classifyTCP(tcp *layers.TCP) model.PortState {
	switch {
	case tcp.SYN && tcp.ACK:
		return model.StateOpen
	case tcp.RST:
		return model.StateClosed
	default:
		return ""
	}
}

// rawNetwork picks the raw socket family. The kernel writes the IP header for
// us in both cases, which is what spares us ARP on v4 and neighbour discovery
// on v6.
func rawNetwork(v6 bool) string {
	if v6 {
		return "ip6:tcp"
	}
	return "ip4:tcp"
}

// bpfReplyFilter admits only replies to this scan: from the target we asked,
// to the ephemeral port we asked from. The family is stated explicitly so a
// v4-mapped form of the same address cannot slip through the v6 filter.
func bpfReplyFilter(dst net.IP, sport uint16, v6 bool) string {
	family := "ip"
	if v6 {
		family = "ip6"
	}
	return fmt.Sprintf("%s and tcp and src host %s and dst port %d", family, dst.String(), sport)
}

// sendSYN writes one SYN. The kernel supplies the IP header; we supply a TCP
// segment whose checksum is computed over the pseudo-header for this pair.
func sendSYN(conn net.PacketConn, src, dst net.IP, sport, dport uint16, v6 bool) error {
	payload, err := buildSYN(src, dst, sport, dport, v6)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(payload, &net.IPAddr{IP: dst})
	return err
}

// buildSYN serializes the TCP segment for one probe. The IP layer is built only
// to compute the checksum: TCP's checksum covers a pseudo-header of the
// addresses, and IPv6's pseudo-header differs from IPv4's, so a v6 probe
// checksummed as v4 would be dropped by the target as corrupt.
func buildSYN(src, dst net.IP, sport, dport uint16, v6 bool) ([]byte, error) {
	var network gopacket.NetworkLayer
	if v6 {
		network = &layers.IPv6{
			Version: 6, HopLimit: 64,
			SrcIP: src, DstIP: dst,
			NextHeader: layers.IPProtocolTCP,
		}
	} else {
		network = &layers.IPv4{
			Version: 4, TTL: 64,
			SrcIP: src, DstIP: dst,
			Protocol: layers.IPProtocolTCP,
		}
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		SYN:     true,
		Seq:     rand.Uint32(),
		Window:  synWindow,
	}
	if err := tcp.SetNetworkLayerForChecksum(network); err != nil {
		return nil, fmt.Errorf("syn scan: %w", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return nil, fmt.Errorf("syn scan: %w", err)
	}
	return buf.Bytes(), nil
}

// synTracker collects per-port state as replies arrive.
type synTracker struct {
	mu       sync.Mutex
	ports    []int
	wanted   map[int]bool // the requested set, so a stray reply can't complete us
	state    map[int]model.PortState
	errors   map[int]error
	complete chan struct{}
	closed   bool
}

func newSYNTracker(ports []int) *synTracker {
	t := &synTracker{
		ports:    append([]int(nil), ports...),
		wanted:   make(map[int]bool, len(ports)),
		state:    make(map[int]model.PortState, len(ports)),
		errors:   map[int]error{},
		complete: make(chan struct{}),
	}
	for _, p := range ports {
		t.wanted[p] = true
	}
	if len(ports) == 0 {
		t.closed = true
		close(t.complete)
	}
	return t
}

// answered closes once every requested port has a state, so the scan can stop
// waiting the moment there is nothing left to wait for.
func (t *synTracker) answered() <-chan struct{} { return t.complete }

// record keeps the first meaningful answer for a port; a later duplicate or an
// uninterpretable flag combination never overwrites it.
func (t *synTracker) record(port int, state model.PortState) {
	if state == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.wanted[port] {
		return // a reply for a port we never asked about proves nothing
	}
	if _, seen := t.state[port]; !seen {
		t.state[port] = state
	}
	if !t.closed && len(t.state) == len(t.wanted) {
		t.closed = true
		close(t.complete)
	}
}

func (t *synTracker) fail(port int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errors[port] = err
}

// pending lists ports that have not answered yet — the retry set.
func (t *synTracker) pending() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []int
	for _, p := range t.ports {
		if _, seen := t.state[p]; !seen {
			out = append(out, p)
		}
	}
	return out
}

// services renders the collected state. Silence, after the retries, is
// filtered: the SYN went out and nothing came back.
func (t *synTracker) services() []model.Service {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]model.Service, 0, len(t.ports))
	for _, p := range t.ports {
		state, ok := t.state[p]
		if !ok {
			state = model.StateFiltered
		}
		out = append(out, model.Service{
			Port: p, Proto: "tcp", State: state, Name: ServiceName(p),
		})
	}
	return out
}

// routeTo asks the kernel which local address and interface would be used to
// reach dst. The UDP "dial" allocates a route and sends nothing — no packet
// leaves the machine for an address the scope has not cleared.
func routeTo(dst net.IP, forced string) (net.IP, string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return nil, "", fmt.Errorf("syn scan: no route to %s: %w", dst, err)
	}
	local := conn.LocalAddr().(*net.UDPAddr).IP
	conn.Close()

	if forced != "" {
		return local, forced, nil
	}
	iface, err := interfaceFor(local)
	if err != nil {
		return nil, "", err
	}
	return local, iface, nil
}

// interfaceFor finds the interface holding a local address.
func interfaceFor(local net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("syn scan: listing interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(local) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("syn scan: no interface holds %s", local)
}

// ephemeralPort picks the source port replies are matched against.
func ephemeralPort() uint16 {
	return uint16(32768 + rand.Intn(28000))
}
