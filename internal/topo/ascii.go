package topo

import (
	"fmt"
	"io"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// WriteASCII draws the graph as an indented tree: subnet, its gateway, then the
// hosts hanging off it. Inferred relationships are called out at the bottom
// rather than dressed up as fact.
func WriteASCII(w io.Writer, s ui.Style, g model.Graph) {
	if g.Empty() {
		fmt.Fprintln(w, s.Dim("nothing to map — no hosts were reached"))
		return
	}

	inferred := 0
	for _, e := range g.Edges {
		if e.Inferred {
			inferred++
		}
	}

	for _, subnet := range g.Nodes {
		if subnet.Kind != model.KindSubnet {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", s.Bold(subnet.ID))

		members := membersOf(g, subnet.ID)
		for i, n := range members {
			branch := "├─"
			if i == len(members)-1 {
				branch = "└─"
			}
			fmt.Fprintf(w, " %s %s\n", s.Dim(branch), hostLine(s, g, n))
		}
	}

	if inferred > 0 {
		fmt.Fprintf(w, "\n%s\n", s.Dim(fmt.Sprintf(
			"%d of %d link(s) inferred from addressing, not observed — see the report for which",
			inferred, len(g.Edges))))
	}
}

// membersOf lists a subnet's nodes with the gateway first, then this host, then
// everything else in the order Build produced.
func membersOf(g model.Graph, subnet string) []model.Node {
	var gw, self, rest []model.Node
	for _, n := range g.Nodes {
		if n.Subnet != subnet || n.Kind == model.KindSubnet {
			continue
		}
		switch n.Kind {
		case model.KindGateway:
			gw = append(gw, n)
		case model.KindThisHost:
			self = append(self, n)
		default:
			rest = append(rest, n)
		}
	}
	return append(append(gw, self...), rest...)
}

func hostLine(s ui.Style, g model.Graph, n model.Node) string {
	parts := []string{changeMark(s, n) + s.Bold(padIP(n.ID))}

	label := n.Label
	if label == n.ID {
		label = s.Dim("unknown host")
	}
	parts = append(parts, pad(label, 22))

	// The note column is padded to a fixed width so the columns after it line
	// up whether or not a row has a note.
	const noteWidth = 22
	switch n.Kind {
	case model.KindGateway:
		parts = append(parts, s.Cyan(pad(gatewayNote(g, n.ID), noteWidth)))
	case model.KindThisHost:
		parts = append(parts, s.Cyan(pad("you are here", noteWidth)))
	default:
		parts = append(parts, pad("", noteWidth))
	}

	if n.Open > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d open", n.Open)))
	}
	if n.Sev != "" && n.Sev.Rank() > model.SevInfo.Rank() {
		parts = append(parts, sevColor(s, n.Sev)("● "+string(n.Sev)))
	}
	if n.Change == model.ChangeWorse || n.Change == model.ChangeBetter {
		was := string(n.PrevSev)
		if was == "" {
			was = "clean"
		}
		parts = append(parts, s.Dim("(was "+was+")"))
	}
	return strings.TrimRight(strings.Join(parts, "  "), " ")
}

// changeMark prefixes a node on a diffed map. An ordinary map has no changes,
// so every line keeps its two leading spaces and nothing shifts.
func changeMark(s ui.Style, n model.Node) string {
	switch n.Change {
	case model.ChangeAdded:
		return s.Yellow("+ ")
	case model.ChangeRemoved:
		return s.Dim("- ")
	case model.ChangeWorse:
		return s.Red("! ")
	case model.ChangeBetter:
		return s.Green("✓ ")
	default:
		return "  "
	}
}

// gatewayNote says whether the router position was watched or assumed.
func gatewayNote(g model.Graph, id string) string {
	for _, e := range g.Edges {
		if e.From != id {
			continue
		}
		if e.Evidence == model.EvDHCP {
			return "gateway · serves DHCP"
		}
	}
	return "gateway · assumed"
}

func sevColor(s ui.Style, sev model.Severity) func(string) string {
	switch sev {
	case model.SevCritical, model.SevHigh:
		return s.Red
	case model.SevMedium:
		return s.Yellow
	case model.SevLow:
		return s.Cyan
	default:
		return s.Dim
	}
}

func padIP(ip string) string { return pad(ip, 15) }

// pad right-pads to width, counting runes so a styled column still lines up.
func pad(s string, w int) string {
	if n := len([]rune(s)); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}
