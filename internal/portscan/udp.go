package portscan

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// UDP scanning is a different problem from TCP, and pretending otherwise is how
// scanners produce confident nonsense. There is no handshake: a service that
// has nothing to say to our probe is indistinguishable from a dropped packet.
// So this engine reports three states, not two — open when something answered,
// closed when the host said "nothing is listening" (ICMP port unreachable,
// which a connected socket surfaces as ECONNREFUSED), and open|filtered for
// silence, which is the truth rather than a coin flip.
//
// It is unprivileged: connected UDP sockets get the ICMP error back from the
// kernel, so no raw socket is needed.

// UDPScanner probes UDP ports with protocol-appropriate payloads.
type UDPScanner struct {
	Timeout     time.Duration // per-port wait for a reply; default 1s
	Concurrency int           // parallel probes per host; default 32
}

// DefaultUDPPorts is a deliberately short list. A full UDP sweep is slow enough
// to be useless, and these are the ports that actually answer and actually
// matter on a LAN.
var DefaultUDPPorts = []int{53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 623, 1900, 5353, 11211}

var udpNames = map[int]string{
	53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 123: "ntp", 137: "netbios-ns",
	138: "netbios-dgm", 161: "snmp", 500: "isakmp", 514: "syslog", 623: "ipmi",
	1900: "ssdp", 5353: "mdns", 11211: "memcached",
}

// UDPServiceName is the well-known name for a UDP port, "" when unknown.
func UDPServiceName(port int) string { return udpNames[port] }

// Scan probes each UDP port on one host.
func (s *UDPScanner) Scan(ctx context.Context, host string, ports []int) ([]model.Service, error) {
	if net.ParseIP(host) == nil {
		return nil, errors.New("udp scan: host must be an IP address")
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = time.Second
	}
	concurrency := s.Concurrency
	if concurrency == 0 {
		concurrency = 32
	}

	out := make([]model.Service, len(ports))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = probeUDP(ctx, host, port, timeout)
		}(i, port)
	}
	wg.Wait()

	// A cancelled scan leaves zero-value entries; drop them rather than report
	// a port we never actually probed.
	result := out[:0]
	for _, svc := range out {
		if svc.Port != 0 {
			result = append(result, svc)
		}
	}
	sort.Slice(result, func(a, b int) bool { return result[a].Port < result[b].Port })
	return result, ctx.Err()
}

// probeUDP sends one datagram and interprets what comes back — or doesn't.
func probeUDP(ctx context.Context, host string, port int, timeout time.Duration) model.Service {
	svc := model.Service{Port: port, Proto: "udp", Name: UDPServiceName(port)}

	d := net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(cctx, "udp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		svc.State = model.StateOpenFiltered
		return svc
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(udpProbe(port)); err != nil {
		if isRefusedUDP(err) {
			svc.State = model.StateClosed
			return svc
		}
		svc.State = model.StateOpenFiltered
		return svc
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	switch {
	case err == nil && n > 0:
		// Something replied: this port is definitely serving.
		svc.State = model.StateOpen
		svc.Banner = sanitizeUDP(buf[:n])
	case isRefusedUDP(err):
		// ICMP port unreachable came back — the host says nothing is listening.
		svc.State = model.StateClosed
	default:
		// Silence. Could be a service with nothing to say, could be a firewall.
		svc.State = model.StateOpenFiltered
	}
	return svc
}

// isRefusedUDP reports whether an error is the kernel surfacing an ICMP port
// unreachable on a connected UDP socket.
func isRefusedUDP(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// sanitizeUDP renders a reply as printable text — services answer in binary as
// often as not, so bytes that aren't text become a length note instead.
func sanitizeUDP(b []byte) string {
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			printable++
		}
	}
	if len(b) == 0 {
		return ""
	}
	if printable*2 < len(b) {
		return itoa(len(b)) + " bytes"
	}
	out := make([]rune, 0, 120)
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, rune(c))
		}
		if len(out) >= 120 {
			break
		}
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
