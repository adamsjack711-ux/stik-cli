package unifi

import (
	"fmt"
	"sort"
	"strings"
)

// The question this tool answers is "what is separated from what, and does the
// separation actually hold". A list of VLANs does not answer it; a VLAN with
// isolation off, sitting beside a guest network with a printer on it, does.

// Segment is one network with everything attached to it.
type Segment struct {
	Network  Network
	Stations []Station
	Notes    []string // observations about this segment's configuration
}

// Map is the whole picture.
type Map struct {
	Site       string
	Segments   []Segment
	Infra      []Infra
	Unassigned []Station // stations whose network the controller did not name
	Firewall   []FirewallRule
	FirewallOK bool
}

// Build assembles the map. Stations are matched by network id first and by
// network name second, because the controller populates one or the other
// depending on how the client connected.
func Build(site string, snap Snapshot) Map {
	m := Map{Site: site, Infra: snap.Infra, Firewall: snap.Firewall, FirewallOK: snap.FirewallOK}

	byID := map[string]int{}
	byName := map[string]int{}
	for _, n := range snap.Networks {
		if n.Purpose == "wan" {
			continue // a WAN is not a segment of the LAN
		}
		seg := Segment{Network: n, Notes: notesFor(n)}
		m.Segments = append(m.Segments, seg)
		idx := len(m.Segments) - 1
		if n.ID != "" {
			byID[n.ID] = idx
		}
		if n.Name != "" {
			byName[strings.ToLower(n.Name)] = idx
		}
	}

	for _, s := range snap.Stations {
		switch {
		case s.NetworkID != "" && hasIndex(byID, s.NetworkID):
			i := byID[s.NetworkID]
			m.Segments[i].Stations = append(m.Segments[i].Stations, s)
		case s.Network != "" && hasIndex(byName, strings.ToLower(s.Network)):
			i := byName[strings.ToLower(s.Network)]
			m.Segments[i].Stations = append(m.Segments[i].Stations, s)
		default:
			m.Unassigned = append(m.Unassigned, s)
		}
	}

	for i := range m.Segments {
		sort.SliceStable(m.Segments[i].Stations, func(a, b int) bool {
			return m.Segments[i].Stations[a].Display() < m.Segments[i].Stations[b].Display()
		})
	}
	sort.SliceStable(m.Segments, func(a, b int) bool {
		return m.Segments[a].Network.Name < m.Segments[b].Network.Name
	})
	sort.SliceStable(m.Unassigned, func(a, b int) bool {
		return m.Unassigned[a].Display() < m.Unassigned[b].Display()
	})
	return m
}

// notesFor states what a segment's configuration means, in the terms someone
// deciding whether to change it would use. These are observations about
// configuration, not vulnerability findings.
func notesFor(n Network) []string {
	var notes []string
	if n.IsGuestNetwork() && !n.Isolated() {
		notes = append(notes,
			"a guest network without isolation: guests can reach each other, and often the LAN")
	}
	if !n.IsGuestNetwork() && n.Isolated() {
		notes = append(notes, "isolated from the other networks")
	}
	if n.Enabled != nil && !*n.Enabled {
		notes = append(notes, "configured but disabled")
	}
	if n.DHCPOn && n.DHCPStart != "" && n.DHCPStop != "" {
		notes = append(notes, fmt.Sprintf("DHCP pool %s–%s", n.DHCPStart, n.DHCPStop))
	}
	if vlan := vlanString(n.VLAN); vlan == "" && n.Purpose != "corporate" {
		notes = append(notes, "no VLAN tag, so this shares the default broadcast domain")
	}
	return notes
}

// vlanString renders the VLAN id, which arrives as a number on some controller
// versions and a string on others.
func vlanString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == 0 {
			return ""
		}
		return fmt.Sprintf("%d", int(t))
	case int:
		if t == 0 {
			return ""
		}
		return fmt.Sprintf("%d", t)
	}
	return ""
}

// GuestSegments are the segments that carry guests, isolated or not.
func (m Map) GuestSegments() []Segment {
	var out []Segment
	for _, s := range m.Segments {
		if s.Network.IsGuestNetwork() {
			out = append(out, s)
		}
	}
	return out
}

// Concerns are the configuration observations worth putting at the top.
func (m Map) Concerns() []string {
	var out []string
	for _, s := range m.Segments {
		if s.Network.IsGuestNetwork() && !s.Network.Isolated() {
			out = append(out, fmt.Sprintf("%q is a guest network with isolation off", s.Network.Name))
		}
	}
	if !m.FirewallOK {
		out = append(out,
			"no firewall rules were readable — on UniFi 10 and later the zone-based firewall "+
				"has no read API, so what this map shows is addressing and isolation flags, not policy")
	}
	return out
}

func hasIndex(m map[string]int, key string) bool {
	_, ok := m[key]
	return ok
}
