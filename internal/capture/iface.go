package capture

import (
	"net"
	"strings"
)

// Candidate is the subset of an interface's properties that interface
// selection cares about. Splitting it out keeps the choice pure and testable
// without a live network stack.
type Candidate struct {
	Name     string
	Up       bool
	Loopback bool
	IPv4s    []string // non-link-local IPv4 addresses on the interface
}

// preferred interface-name prefixes, most-likely-LAN first.
var preferredPrefixes = []string{"en", "eth", "wlan", "wlp", "enp"}

// chooseInterface picks the interface stik should listen on. The user never
// has to choose: we take an up, non-loopback interface that has a real IPv4
// address, preferring conventional wired/Wi-Fi names over virtual ones.
func chooseInterface(candidates []Candidate) (string, bool) {
	var usable []Candidate
	for _, c := range candidates {
		if c.Up && !c.Loopback && len(c.IPv4s) > 0 {
			usable = append(usable, c)
		}
	}
	if len(usable) == 0 {
		return "", false
	}
	// Prefer a conventional physical interface name.
	for _, prefix := range preferredPrefixes {
		for _, c := range usable {
			if strings.HasPrefix(c.Name, prefix) && !isVirtual(c.Name) {
				return c.Name, true
			}
		}
	}
	// Otherwise the first usable non-virtual interface, else the first usable.
	for _, c := range usable {
		if !isVirtual(c.Name) {
			return c.Name, true
		}
	}
	return usable[0].Name, true
}

// isVirtual flags tunnels, bridges, and VPNs we'd rather not bind to when a
// real LAN interface exists.
func isVirtual(name string) bool {
	for _, v := range []string{"utun", "tun", "tap", "bridge", "vboxnet", "vmnet", "llw", "awdl", "gif", "stf", "ipsec"} {
		if strings.HasPrefix(name, v) {
			return true
		}
	}
	return false
}

// gatherCandidates reads the live interface list into Candidates.
func gatherCandidates() ([]Candidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Candidate
	for _, ifi := range ifaces {
		c := Candidate{
			Name:     ifi.Name,
			Up:       ifi.Flags&net.FlagUp != 0,
			Loopback: ifi.Flags&net.FlagLoopback != 0,
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() && !ip4.IsLoopback() {
				c.IPv4s = append(c.IPv4s, ip4.String())
			}
		}
		out = append(out, c)
	}
	return out, nil
}
