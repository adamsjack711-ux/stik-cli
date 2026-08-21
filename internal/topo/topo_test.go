package topo

import (
	"net"
	"strings"
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

func host(ip string, open ...int) model.Host {
	h := model.Host{IP: ip, Up: true}
	for _, p := range open {
		h.Services = append(h.Services, model.Service{Port: p, Proto: "tcp", State: model.StateOpen})
	}
	return h
}

func nodeByID(t *testing.T, g model.Graph, id string) model.Node {
	t.Helper()
	n, ok := g.NodeByID(id)
	if !ok {
		t.Fatalf("no node %q in graph %+v", id, g.Nodes)
	}
	return n
}

func edgeFrom(g model.Graph, from string) (model.Edge, bool) {
	for _, e := range g.Edges {
		if e.From == from {
			return e, true
		}
	}
	return model.Edge{}, false
}

func TestGatewayFromObservedDHCP(t *testing.T) {
	g := Build(Input{
		Hosts:       []model.Host{host("192.168.1.1"), host("192.168.1.50", 22)},
		Subnets:     []*net.IPNet{cidr(t, "192.168.1.0/24")},
		DHCPServers: map[string]bool{"192.168.1.1": true},
	})

	if n := nodeByID(t, g, "192.168.1.1"); n.Kind != model.KindGateway {
		t.Errorf("kind = %q, want gateway", n.Kind)
	}
	e, ok := edgeFrom(g, "192.168.1.1")
	if !ok {
		t.Fatal("gateway has no edge")
	}
	// Watching a host hand out leases is an observation, not a guess.
	if e.Evidence != model.EvDHCP || e.Inferred {
		t.Errorf("edge = %s/inferred=%v, want dhcp/false", e.Evidence, e.Inferred)
	}
	if len(g.Roots) != 1 || g.Roots[0] != "192.168.1.1" {
		t.Errorf("roots = %v, want the gateway", g.Roots)
	}
}

func TestGatewayFallbackIsMarkedInferred(t *testing.T) {
	// No DHCP evidence: .1 is a convention, and the map must say so.
	g := Build(Input{
		Hosts:   []model.Host{host("10.0.0.1"), host("10.0.0.7")},
		Subnets: []*net.IPNet{cidr(t, "10.0.0.0/24")},
	})
	if n := nodeByID(t, g, "10.0.0.1"); n.Kind != model.KindGateway {
		t.Errorf("kind = %q, want gateway", n.Kind)
	}
	e, _ := edgeFrom(g, "10.0.0.1")
	if e.Evidence != model.EvGateway || !e.Inferred {
		t.Errorf("edge = %s/inferred=%v, want gateway/true", e.Evidence, e.Inferred)
	}
}

func TestNoGatewayLeavesSubnetAsRoot(t *testing.T) {
	g := Build(Input{
		Hosts:   []model.Host{host("10.0.0.7"), host("10.0.0.9")},
		Subnets: []*net.IPNet{cidr(t, "10.0.0.0/24")},
	})
	if len(g.Roots) != 1 || g.Roots[0] != "10.0.0.0/24" {
		t.Errorf("roots = %v, want the subnet itself", g.Roots)
	}
	for _, n := range g.Nodes {
		if n.Kind == model.KindGateway {
			t.Errorf("invented a gateway: %+v", n)
		}
	}
}

func TestARPEvidenceBeatsSubnetArithmetic(t *testing.T) {
	g := Build(Input{
		Hosts:   []model.Host{host("192.168.1.50", 445)},
		Subnets: []*net.IPNet{cidr(t, "192.168.1.0/24")},
		MACs:    map[string]string{"192.168.1.50": "aa:bb:cc:dd:ee:ff"},
	})
	e, _ := edgeFrom(g, "192.168.1.50")
	if e.Evidence != model.EvARP || e.Inferred {
		t.Errorf("edge = %s/inferred=%v, want arp/false", e.Evidence, e.Inferred)
	}
	if n := nodeByID(t, g, "192.168.1.50"); n.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q, want it carried onto the node", n.MAC)
	}
}

func TestSameSubnetEdgesAreInferred(t *testing.T) {
	g := Build(Input{
		Hosts:   []model.Host{host("192.168.1.50")},
		Subnets: []*net.IPNet{cidr(t, "192.168.1.0/24")},
	})
	e, _ := edgeFrom(g, "192.168.1.50")
	if e.Evidence != model.EvSameSubnet || !e.Inferred {
		t.Errorf("edge = %s/inferred=%v, want same-subnet/true", e.Evidence, e.Inferred)
	}
}

func TestThisHostIsMarked(t *testing.T) {
	g := Build(Input{
		Hosts:    []model.Host{host("192.168.1.50"), host("192.168.1.77")},
		Subnets:  []*net.IPNet{cidr(t, "192.168.1.0/24")},
		LocalIPs: []string{"192.168.1.77"},
	})
	if n := nodeByID(t, g, "192.168.1.77"); n.Kind != model.KindThisHost {
		t.Errorf("kind = %q, want this-host", n.Kind)
	}
}

func TestLocalAddressAbsentFromScanStillAppears(t *testing.T) {
	g := Build(Input{
		Hosts:    []model.Host{host("192.168.1.50")},
		Subnets:  []*net.IPNet{cidr(t, "192.168.1.0/24")},
		LocalIPs: []string{"192.168.1.200"},
	})
	if n := nodeByID(t, g, "192.168.1.200"); n.Kind != model.KindThisHost {
		t.Errorf("kind = %q, want this-host on the map even though the scan skipped it", n.Kind)
	}
}

func TestLocalAddressInAnUnscannedSubnetIsNotInvented(t *testing.T) {
	g := Build(Input{
		Hosts:    []model.Host{host("192.168.1.50")},
		Subnets:  []*net.IPNet{cidr(t, "192.168.1.0/24")},
		LocalIPs: []string{"10.9.9.9"},
	})
	if _, ok := g.NodeByID("10.9.9.9"); ok {
		t.Error("an address in a subnet this run never covered must not create one")
	}
}

func TestSeverityAndOpenCountRollUp(t *testing.T) {
	hosts := []model.Host{host("192.168.1.20", 445, 139, 22)}
	g := Build(Input{
		Hosts:   hosts,
		Subnets: []*net.IPNet{cidr(t, "192.168.1.0/24")},
		Findings: []model.Finding{
			{Host: "192.168.1.20", Severity: model.SevLow, Title: "low"},
			{Host: "192.168.1.20", Severity: model.SevHigh, Title: "high"},
			{Host: "192.168.1.20", Severity: model.SevMedium, Title: "medium"},
		},
	})
	n := nodeByID(t, g, "192.168.1.20")
	if n.Sev != model.SevHigh {
		t.Errorf("node severity = %q, want the worst finding (high)", n.Sev)
	}
	if n.Open != 3 {
		t.Errorf("open = %d, want 3", n.Open)
	}
	if s := nodeByID(t, g, "192.168.1.0/24"); s.Sev != model.SevHigh {
		t.Errorf("subnet severity = %q, want the worst of its hosts", s.Sev)
	}
}

func TestHostsGroupIntoTheirOwnSubnets(t *testing.T) {
	g := Build(Input{
		Hosts:   []model.Host{host("192.168.1.5"), host("10.0.0.5")},
		Subnets: []*net.IPNet{cidr(t, "192.168.1.0/24"), cidr(t, "10.0.0.0/24")},
	})
	if n := nodeByID(t, g, "192.168.1.5"); n.Subnet != "192.168.1.0/24" {
		t.Errorf("subnet = %q", n.Subnet)
	}
	if n := nodeByID(t, g, "10.0.0.5"); n.Subnet != "10.0.0.0/24" {
		t.Errorf("subnet = %q", n.Subnet)
	}
	if len(g.Roots) != 2 {
		t.Errorf("roots = %v, want one per subnet", g.Roots)
	}
}

func TestHostOutsideEveryScopeStillLands(t *testing.T) {
	// Nothing may be dropped silently off the map.
	g := Build(Input{Hosts: []model.Host{host("172.16.4.9")}})
	n := nodeByID(t, g, "172.16.4.9")
	if n.Subnet != "172.16.4.0/24" {
		t.Errorf("subnet = %q, want the natural /24 fallback", n.Subnet)
	}
}

func TestMostSpecificScopeRangeWins(t *testing.T) {
	g := Build(Input{
		Hosts:   []model.Host{host("192.168.1.20")},
		Subnets: []*net.IPNet{cidr(t, "192.168.1.0/24"), cidr(t, "192.168.1.20/32")},
	})
	if n := nodeByID(t, g, "192.168.1.20"); n.Subnet != "192.168.1.20/32" {
		t.Errorf("subnet = %q, want the /32", n.Subnet)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	in := Input{
		Hosts:   []model.Host{host("192.168.1.9"), host("192.168.1.10"), host("192.168.1.2")},
		Subnets: []*net.IPNet{cidr(t, "192.168.1.0/24")},
	}
	first := Build(in)
	for i := 0; i < 10; i++ {
		got := Build(in)
		if len(got.Nodes) != len(first.Nodes) {
			t.Fatalf("node count drifted")
		}
		for j := range got.Nodes {
			if got.Nodes[j].ID != first.Nodes[j].ID {
				t.Fatalf("node order drifted at %d: %s vs %s", j, got.Nodes[j].ID, first.Nodes[j].ID)
			}
		}
	}
	// .2 before .9 before .10 — numeric, not lexical.
	var ips []string
	for _, n := range first.Nodes {
		if n.Kind != model.KindSubnet {
			ips = append(ips, n.ID)
		}
	}
	want := []string{"192.168.1.2", "192.168.1.9", "192.168.1.10"}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("host order = %v, want %v", ips, want)
		}
	}
}

func TestWriteASCII(t *testing.T) {
	g := Build(Input{
		Hosts:       []model.Host{host("192.168.1.1"), host("192.168.1.20", 445), host("192.168.1.77")},
		Subnets:     []*net.IPNet{cidr(t, "192.168.1.0/24")},
		Names:       map[string]string{"192.168.1.20": "Jack's NAS"},
		DHCPServers: map[string]bool{"192.168.1.1": true},
		LocalIPs:    []string{"192.168.1.77"},
		Findings:    []model.Finding{{Host: "192.168.1.20", Severity: model.SevHigh, Title: "SMB"}},
	})
	var sb strings.Builder
	WriteASCII(&sb, ui.Style{}, g)
	out := sb.String()

	for _, want := range []string{
		"192.168.1.0/24",
		"gateway · serves DHCP",
		"Jack's NAS",
		"1 open",
		"● high",
		"you are here",
		"inferred from addressing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ascii map missing %q\n---\n%s", want, out)
		}
	}
	// The gateway is the first thing under its subnet.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.Contains(lines[1], "192.168.1.1") {
		t.Errorf("gateway should head the subnet, got %q", lines[1])
	}
}

func TestWriteASCIIOnEmptyGraph(t *testing.T) {
	var sb strings.Builder
	WriteASCII(&sb, ui.Style{}, model.Graph{})
	if !strings.Contains(sb.String(), "nothing to map") {
		t.Errorf("empty map should say so: %q", sb.String())
	}
}
