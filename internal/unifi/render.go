package unifi

import (
	"fmt"
	"io"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// WriteText renders the segmentation map for a terminal. It reuses stik-net's
// style so the two tools read as one family, and it leads with what is worth
// acting on rather than burying it under an inventory.
func WriteText(w io.Writer, s ui.Style, m Map) {
	fmt.Fprintf(w, "\n%s  %s\n", s.Bold("UniFi segmentation"), s.Dim("site "+m.Site))

	if concerns := m.Concerns(); len(concerns) > 0 {
		fmt.Fprintln(w)
		for _, c := range concerns {
			fmt.Fprintf(w, "  %s %s\n", s.Yellow("!"), c)
		}
	}

	fmt.Fprintf(w, "\n%s\n", s.Bold("networks"))
	if len(m.Segments) == 0 {
		fmt.Fprintln(w, "  "+s.Dim("the controller reported no LAN networks"))
	}
	for _, seg := range m.Segments {
		writeSegment(w, s, seg)
	}

	if len(m.Unassigned) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", s.Bold("not attributed to a network"),
			s.Dim("(the controller did not say which)"))
		for _, st := range m.Unassigned {
			fmt.Fprintf(w, "    %s\n", stationLine(s, st))
		}
	}

	if len(m.Infra) > 0 {
		fmt.Fprintf(w, "\n%s\n", s.Bold("infrastructure"))
		for _, d := range m.Infra {
			name := d.Name
			if name == "" {
				name = d.Model
			}
			state := s.Green("connected")
			if d.State != 1 {
				state = s.Yellow("not connected")
			}
			fmt.Fprintf(w, "    %s  %s  %s  %s\n",
				s.Bold(pad(name, 22)), pad(kindOf(d.Type), 14), state, s.Dim(d.MAC))
		}
	}

	if m.FirewallOK {
		fmt.Fprintf(w, "\n%s\n", s.Bold("firewall rules"))
		for _, r := range m.Firewall {
			if !r.Enabled {
				continue
			}
			fmt.Fprintf(w, "    %s  %s  %s\n",
				s.Bold(pad(r.Ruleset, 12)), pad(r.Action, 8), r.Name)
		}
	}

	fmt.Fprintf(w, "\n%s\n", s.Dim(
		"read-only: this tool only ever issues GETs, and never reads the CSRF token "+
			"a controller requires before it will accept a change."))
}

func writeSegment(w io.Writer, s ui.Style, seg Segment) {
	n := seg.Network
	title := n.Name
	if title == "" {
		title = "(unnamed)"
	}
	bits := []string{}
	if v := vlanString(n.VLAN); v != "" {
		bits = append(bits, "VLAN "+v)
	}
	if n.Subnet != "" {
		bits = append(bits, n.Subnet)
	}
	if n.Purpose != "" {
		bits = append(bits, n.Purpose)
	}

	marker := s.Green("○")
	if n.IsGuestNetwork() && !n.Isolated() {
		marker = s.Yellow("!")
	}
	fmt.Fprintf(w, "\n  %s %s  %s\n", marker, s.Bold(title), s.Dim(strings.Join(bits, " · ")))

	for _, note := range seg.Notes {
		fmt.Fprintf(w, "      %s\n", s.Dim(note))
	}
	if len(seg.Stations) == 0 {
		fmt.Fprintf(w, "      %s\n", s.Dim("nothing connected"))
		return
	}
	for _, st := range seg.Stations {
		fmt.Fprintf(w, "      %s\n", stationLine(s, st))
	}
}

func stationLine(s ui.Style, st Station) string {
	how := "wireless"
	if st.IsWired {
		how = "wired"
	}
	line := fmt.Sprintf("%s  %s  %s", s.Bold(pad(st.Display(), 24)), pad(st.IP, 15), s.Dim(how))
	if st.IsGuest {
		line += "  " + s.Dim("guest")
	}
	return line
}

func kindOf(t string) string {
	switch t {
	case "ugw", "udm":
		return "gateway"
	case "usw":
		return "switch"
	case "uap":
		return "access point"
	}
	return t
}

func pad(s string, w int) string {
	if n := len([]rune(s)); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}
