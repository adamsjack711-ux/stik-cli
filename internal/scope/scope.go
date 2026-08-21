// Package scope is the authorization gate for every active operation. Nothing
// in stik-net's audit path may touch an address that scope has not cleared.
//
// A scope is loaded from a plain file of authorized targets — one CIDR or IP
// per line, with `#` comments and blank lines ignored — and answers a single
// security-critical question: is this address in bounds? An empty or unloaded
// scope matches nothing (fail closed), so a bug or a missing file can never
// widen the blast radius; it can only refuse to scan.
package scope

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Set is a parsed, immutable collection of authorized targets. The zero value
// is a valid empty scope that contains nothing.
type Set struct {
	nets   []*net.IPNet // CIDRs and single hosts (as /32 or /128)
	raw    []string     // the authorized lines, verbatim, for the report header
	source string       // file path or "<inline>", for provenance
	sumHex string       // sha256 of the normalized entries, for the report header
}

// Load reads and parses a scope file. A file with no valid entries is an error:
// an accidental empty scope should stop the run loudly, not silently authorize
// nothing and look like a clean scan.
func Load(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open scope file: %w", err)
	}
	defer f.Close()

	s, err := Parse(f)
	if err != nil {
		return nil, err
	}
	if s.Empty() {
		return nil, fmt.Errorf("scope file %q has no authorized targets", path)
	}
	s.source = path
	return s, nil
}

// Parse reads scope entries from any reader. Each non-comment, non-blank line
// must be a CIDR ("192.168.1.0/24") or a bare IP ("10.0.0.5", promoted to a
// host route). The first malformed entry fails the whole parse — a scope you
// cannot fully trust is not a scope.
func Parse(r io.Reader) (*Set, error) {
	s := &Set{source: "<inline>"}
	sc := bufio.NewScanner(r)
	line := 0
	h := sha256.New()
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}
		n, err := parseEntry(text)
		if err != nil {
			return nil, fmt.Errorf("scope line %d: %w", line, err)
		}
		s.nets = append(s.nets, n)
		s.raw = append(s.raw, text)
		fmt.Fprintln(h, n.String())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	s.sumHex = hex.EncodeToString(h.Sum(nil))
	return s, nil
}

// parseEntry turns one line into a network. A bare IP becomes a single-host
// network (/32 for v4, /128 for v6) so all matching goes through one code path.
func parseEntry(text string) (*net.IPNet, error) {
	if _, n, err := net.ParseCIDR(text); err == nil {
		return n, nil
	}
	ip := net.ParseIP(text)
	if ip == nil {
		return nil, fmt.Errorf("not an IP or CIDR: %q", text)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// Contains reports whether ip is authorized. This is the gate: every active
// package must call it — and heed a false — before sending a single packet to
// an address. A nil or empty Set always returns false.
func (s *Set) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ContainsHost is Contains for a string host, tolerant of a "host:port" form.
// A hostname (non-literal) is rejected — the gate matches IPs only, so callers
// resolve names first and re-check every resolved address.
func (s *Set) ContainsHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return s.Contains(net.ParseIP(strings.TrimSpace(host)))
}

// Nets returns the authorized networks. Callers enumerate candidates from these
// and must still filter each one through Contains — enumeration is convenience,
// Contains is the authority.
func (s *Set) Nets() []*net.IPNet {
	if s == nil {
		return nil
	}
	out := make([]*net.IPNet, len(s.nets))
	copy(out, s.nets)
	return out
}

// Empty reports whether the scope authorizes nothing.
func (s *Set) Empty() bool { return s == nil || len(s.nets) == 0 }

// Entries returns the authorized lines verbatim, for a report header.
func (s *Set) Entries() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.raw))
	copy(out, s.raw)
	return out
}

// Source is where the scope came from (file path or "<inline>").
func (s *Set) Source() string {
	if s == nil {
		return ""
	}
	return s.source
}

// Fingerprint is a short, stable hash of the authorized set, so a report can
// prove which scope a run was cleared against.
func (s *Set) Fingerprint() string {
	if s == nil || s.sumHex == "" {
		return ""
	}
	return s.sumHex[:12]
}
