package model

import (
	"net"
	"time"
)

// Host is an IP-keyed record produced by the active audit path, as distinct
// from Device (which is MAC-keyed passive identity). When the passive registry
// has seen this IP's MAC, MAC is filled in so the audit can borrow the device's
// friendly name instead of showing a bare address.
type Host struct {
	IP           string    `json:"ip"`
	MAC          string    `json:"mac,omitempty"`
	Up           bool      `json:"up"`
	DiscoveredBy string    `json:"discovered_by"`      // e.g. "tcp-ping"
	Services     []Service `json:"services,omitempty"` // filled by the port scan
	ScannedAt    time.Time `json:"scanned_at"`
}

// PortState is the outcome of probing one TCP port.
type PortState string

const (
	StateOpen     PortState = "open"     // handshake completed, or a UDP service replied
	StateClosed   PortState = "closed"   // actively refused (TCP RST, or ICMP port unreachable)
	StateFiltered PortState = "filtered" // no response before timeout

	// StateOpenFiltered is UDP's honest answer to silence. A UDP service that
	// has nothing to say to our probe looks exactly like a dropped packet, and
	// there is no way to tell them apart from outside. Reporting either "open"
	// or "filtered" here would be a guess dressed as a result.
	StateOpenFiltered PortState = "open|filtered"
)

// Service is one port's result. M2 records reachability (Port/State/Name);
// the M3 fingerprint pass fills Product/Version/Banner/TLS from the wire.
type Service struct {
	Port    int       `json:"port"`
	Proto   string    `json:"proto"` // "tcp" or "udp"
	State   PortState `json:"state"`
	Name    string    `json:"name,omitempty"`    // well-known name, e.g. "https"
	Product string    `json:"product,omitempty"` // e.g. "OpenSSH", "nginx"
	Version string    `json:"version,omitempty"` // e.g. "9.6", "1.25.3"
	Banner  string    `json:"banner,omitempty"`  // sanitized, truncated
	TLS     *TLSInfo  `json:"tls,omitempty"`
}

// TLSInfo is what the fingerprint pass reads from a service's TLS handshake and
// leaf certificate. It is diagnostic, not a trust decision — the scan verifies
// nothing, it only reports what the service presents.
type TLSInfo struct {
	Version    string   `json:"version"`               // "TLS 1.3", "TLS 1.0"
	Subject    string   `json:"subject,omitempty"`     // leaf cert CN
	Issuer     string   `json:"issuer,omitempty"`      // issuer CN
	NotAfter   string   `json:"not_after,omitempty"`   // RFC3339 expiry
	Expired    bool     `json:"expired,omitempty"`     // NotAfter is in the past
	SelfSigned bool     `json:"self_signed,omitempty"` // subject == issuer
	DNSNames   []string `json:"dns_names,omitempty"`   // SANs
}

// LessIP orders addresses numerically rather than lexically, so .9 sorts before
// .10 and a report re-run on an unchanged network reads the same way twice.
func LessIP(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	a16, b16 := ia.To16(), ib.To16()
	for i := range a16 {
		if a16[i] != b16[i] {
			return a16[i] < b16[i]
		}
	}
	return false
}
