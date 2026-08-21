package topo

import (
	"net"
	"strings"
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

func graphOf(t *testing.T, hosts []model.Host, findings []model.Finding) model.Graph {
	t.Helper()
	return Build(Input{
		Hosts:    hosts,
		Findings: findings,
		Subnets:  []*net.IPNet{cidr(t, "192.168.1.0/24")},
	})
}

func changeOf(t *testing.T, g model.Graph, id string) model.NodeChange {
	t.Helper()
	n, ok := g.NodeByID(id)
	if !ok {
		t.Fatalf("no node %q on the diffed map", id)
	}
	return n.Change
}

func TestDiffGraphsMarksAddedAndRemovedHosts(t *testing.T) {
	before := graphOf(t, []model.Host{host("192.168.1.10", 22)}, nil)
	after := graphOf(t, []model.Host{host("192.168.1.10", 22), host("192.168.1.50", 445)}, nil)

	d := DiffGraphs(before, after)
	if len(d.Added) != 1 || d.Added[0].ID != "192.168.1.50" {
		t.Errorf("added = %+v, want the new host", d.Added)
	}
	if changeOf(t, d.Graph, "192.168.1.50") != model.ChangeAdded {
		t.Error("the new host should be marked added on the union map")
	}
	if changeOf(t, d.Graph, "192.168.1.10") != "" {
		t.Error("an unchanged host should carry no marker")
	}

	back := DiffGraphs(after, before)
	if len(back.Removed) != 1 || back.Removed[0].ID != "192.168.1.50" {
		t.Errorf("removed = %+v, want the departed host", back.Removed)
	}
	// A removed node is carried over from the earlier map: the picture should
	// still show where it used to sit.
	if _, ok := back.Graph.NodeByID("192.168.1.50"); !ok {
		t.Error("a removed host must still appear on the diffed map")
	}
}

func TestDiffGraphsMarksSeverityMovingBothWays(t *testing.T) {
	hosts := []model.Host{host("192.168.1.10", 22)}
	clean := graphOf(t, hosts, nil)
	bad := graphOf(t, hosts, []model.Finding{{Host: "192.168.1.10", Severity: model.SevHigh, Title: "x"}})

	worse := DiffGraphs(clean, bad)
	if len(worse.Worse) != 1 || changeOf(t, worse.Graph, "192.168.1.10") != model.ChangeWorse {
		t.Errorf("want the host marked worse, got %+v", worse.Worse)
	}
	if worse.Worse[0].PrevSev == worse.Worse[0].Sev {
		t.Error("a worsened node should carry what it was before")
	}

	better := DiffGraphs(bad, clean)
	if len(better.Better) != 1 || changeOf(t, better.Graph, "192.168.1.10") != model.ChangeBetter {
		t.Errorf("want the host marked better, got %+v", better.Better)
	}
	if better.Better[0].PrevSev != model.SevHigh {
		t.Errorf("prev severity = %q, want high", better.Better[0].PrevSev)
	}
}

func TestDiffGraphsOfIdenticalMapsIsEmpty(t *testing.T) {
	g := graphOf(t, []model.Host{host("192.168.1.10", 22), host("192.168.1.50", 445)}, nil)
	d := DiffGraphs(g, g)
	if !d.Empty() {
		t.Errorf("identical maps should diff to nothing: %+v", d)
	}
	for _, n := range d.Graph.Nodes {
		if n.Change != "" {
			t.Errorf("node %s carries %q on an unchanged map", n.ID, n.Change)
		}
	}
}

func TestDiffGraphsMarksNewEdges(t *testing.T) {
	before := graphOf(t, []model.Host{host("192.168.1.10", 22)}, nil)
	after := graphOf(t, []model.Host{host("192.168.1.10", 22), host("192.168.1.50", 445)}, nil)

	d := DiffGraphs(before, after)
	var added int
	for _, e := range d.Graph.Edges {
		if e.Change == model.ChangeAdded {
			added++
			if e.From != "192.168.1.50" {
				t.Errorf("added edge from %s, want the new host's", e.From)
			}
		}
	}
	if added != 1 {
		t.Errorf("added edges = %d, want 1", added)
	}
}

func TestWriteASCIIShowsChangeMarkers(t *testing.T) {
	before := graphOf(t, []model.Host{host("192.168.1.10", 22), host("192.168.1.60", 80)}, nil)
	after := graphOf(t, []model.Host{host("192.168.1.10", 22), host("192.168.1.50", 445)},
		[]model.Finding{{Host: "192.168.1.10", Severity: model.SevMedium, Title: "x"}})

	var sb strings.Builder
	WriteASCII(&sb, ui.Style{}, DiffGraphs(before, after).Graph)
	out := sb.String()

	for _, want := range []string{
		"+ 192.168.1.50", // appeared
		"- 192.168.1.60", // gone
		"! 192.168.1.10", // got worse
		"(was clean)",    // and what it was before
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diffed tree missing %q\n---\n%s", want, out)
		}
	}
}

func TestWriteASCIIOnAnUndiffedMapHasNoMarkers(t *testing.T) {
	var sb strings.Builder
	WriteASCII(&sb, ui.Style{}, graphOf(t, []model.Host{host("192.168.1.10", 22)}, nil))
	for _, marker := range []string{"+ 192", "- 192", "! 192", "✓ 192"} {
		if strings.Contains(sb.String(), marker) {
			t.Errorf("an ordinary map should carry no change markers: %q", sb.String())
		}
	}
}

func TestDiffedMapRendersItsLegendAndHTMLStaysSelfContained(t *testing.T) {
	before := graphOf(t, []model.Host{host("192.168.1.10", 22)}, nil)
	after := graphOf(t, []model.Host{host("192.168.1.10", 22), host("192.168.1.50", 445)}, nil)
	d := DiffGraphs(before, after)

	frag, err := Fragment(ViewFrom(d.Graph, nil, nil))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	out := string(frag)
	if !strings.Contains(out, "added") || !strings.Contains(out, "ring") {
		t.Error("a diffed map should explain its markers in the legend")
	}
	for _, forbidden := range []string{"src=", "http://", "https://"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("diffed map reaches outside: %q", forbidden)
		}
	}

	plain, err := Fragment(ViewFrom(before, nil, nil))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	if strings.Contains(string(plain), `class="ring`) {
		t.Error("an ordinary map should not show the change legend")
	}
}

func TestSubnetRollUpIsNotCountedAsItsOwnChange(t *testing.T) {
	// One host getting worse drags its subnet's severity up with it. That is one
	// event, not two — the subnet is coloured but never counted.
	hosts := []model.Host{host("192.168.1.10", 445)}
	before := graphOf(t, hosts, nil)
	after := graphOf(t, hosts, []model.Finding{{Host: "192.168.1.10", Severity: model.SevHigh, Title: "x"}})

	d := DiffGraphs(before, after)
	if len(d.Worse) != 1 {
		t.Fatalf("worse = %d nodes, want just the host", len(d.Worse))
	}
	if d.Worse[0].Kind == model.KindSubnet {
		t.Error("the subnet was counted instead of the host")
	}
	if changeOf(t, d.Graph, "192.168.1.0/24") != model.ChangeWorse {
		t.Error("the subnet should still be coloured, just not counted")
	}
}
