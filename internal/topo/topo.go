// Package topo infers the shape of a network from what the scan and the passive
// watcher already know, and draws it two ways: an indented tree for a terminal
// and a self-contained interactive graph for the report.
//
// It is inference, and it says so. Every edge carries the evidence that put it
// there, and the renderers draw observed relationships solid and reasoned ones
// dashed. stik-net never claims to know your cabling — it knows who answered,
// who hands out leases, and which addresses share a subnet.
package topo

import (
	"net"
	"sort"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Input is everything the inference draws on. Every field is optional: with
// only Hosts you still get a usable map, and each extra source (the registry's
// names and DHCP knowledge, the local interface list) sharpens it.
type Input struct {
	Hosts       []model.Host
	Findings    []model.Finding
	Names       map[string]string // IP → friendly device name
	MACs        map[string]string // IP → MAC, from the passive registry
	DHCPServers map[string]bool   // IP → seen handing out DHCP leases
	Subnets     []*net.IPNet      // the authorized ranges, from the scope file
	LocalIPs    []string          // addresses of the machine stik-net ran on
}

// Build turns scan results into a graph. It performs no I/O and sends no
// packets — redrawing a stored run can never touch the network.
func Build(in Input) model.Graph {
	worst := worstByHost(in.Findings)
	local := stringSet(in.LocalIPs)

	// Group hosts by the subnet they fall in. A host outside every known subnet
	// still gets a home, keyed by its own /24-ish prefix, so nothing is dropped
	// silently off the map.
	subnetOf := map[string]string{}
	members := map[string][]model.Host{}
	var order []string
	for _, h := range in.Hosts {
		cidr := subnetFor(h.IP, in.Subnets)
		if _, seen := members[cidr]; !seen {
			order = append(order, cidr)
		}
		subnetOf[h.IP] = cidr
		members[cidr] = append(members[cidr], h)
	}
	sort.Strings(order)

	g := model.Graph{}
	for _, cidr := range order {
		hosts := members[cidr]
		sort.Slice(hosts, func(i, j int) bool { return lessIP(hosts[i].IP, hosts[j].IP) })

		gateway := pickGateway(hosts, cidr, in.DHCPServers)
		g.Nodes = append(g.Nodes, model.Node{
			ID: cidr, Kind: model.KindSubnet, Label: cidr, Subnet: cidr,
			Sev: worstIn(hosts, worst),
		})

		for _, h := range hosts {
			kind := model.KindHost
			switch {
			case h.IP == gateway:
				kind = model.KindGateway
			case local[h.IP]:
				kind = model.KindThisHost
			}
			g.Nodes = append(g.Nodes, model.Node{
				ID:     h.IP,
				Kind:   kind,
				Label:  labelFor(h.IP, in.Names),
				Subnet: cidr,
				Sev:    worst[h.IP],
				Open:   openCount(h),
				MAC:    in.MACs[h.IP],
			})
			g.Edges = append(g.Edges, edgeFor(h, cidr, kind, in))
		}

		if gateway != "" {
			g.Roots = append(g.Roots, gateway)
		} else {
			g.Roots = append(g.Roots, cidr)
		}
	}

	// A local address the scan never reported still belongs on the map: the
	// reader needs to see where they are standing.
	for _, ip := range in.LocalIPs {
		if _, exists := g.NodeByID(ip); exists {
			continue
		}
		cidr := subnetFor(ip, in.Subnets)
		if _, known := members[cidr]; !known {
			continue // not a subnet this run covered — don't invent one
		}
		g.Nodes = append(g.Nodes, model.Node{
			ID: ip, Kind: model.KindThisHost, Label: labelFor(ip, in.Names), Subnet: cidr,
		})
		g.Edges = append(g.Edges, model.Edge{From: ip, To: cidr, Evidence: model.EvLocal})
	}

	return g
}

// edgeFor picks the strongest evidence available for a host's link to its
// subnet. DHCP and ARP are things the watcher actually saw; same-subnet is
// arithmetic on the address, so it stays marked inferred.
func edgeFor(h model.Host, cidr string, kind model.NodeKind, in Input) model.Edge {
	switch {
	case in.DHCPServers[h.IP]:
		return model.Edge{From: h.IP, To: cidr, Evidence: model.EvDHCP}
	case kind == model.KindThisHost:
		return model.Edge{From: h.IP, To: cidr, Evidence: model.EvLocal}
	case in.MACs[h.IP] != "":
		return model.Edge{From: h.IP, To: cidr, Evidence: model.EvARP}
	case kind == model.KindGateway:
		return model.Edge{From: h.IP, To: cidr, Evidence: model.EvGateway, Inferred: true}
	default:
		return model.Edge{From: h.IP, To: cidr, Evidence: model.EvSameSubnet, Inferred: true}
	}
}

// pickGateway prefers a host the passive watcher saw handing out DHCP leases —
// that is observed. Failing that it falls back to the first usable address in
// the subnet, which is a convention, not a fact, and is marked inferred by
// edgeFor.
func pickGateway(hosts []model.Host, cidr string, dhcp map[string]bool) string {
	for _, h := range hosts {
		if dhcp[h.IP] {
			return h.IP
		}
	}
	first := firstUsable(cidr)
	for _, h := range hosts {
		if h.IP == first {
			return h.IP
		}
	}
	return ""
}

// subnetFor places an address in one of the authorized ranges, falling back to
// its natural /24 (or /64) so a host is never lost.
func subnetFor(ip string, subnets []*net.IPNet) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	best := ""
	bestOnes := -1
	for _, n := range subnets {
		if !n.Contains(parsed) {
			continue
		}
		// Most specific range wins, so a /32 target doesn't swallow the /24.
		if ones, _ := n.Mask.Size(); ones > bestOnes {
			best, bestOnes = n.String(), ones
		}
	}
	if best != "" {
		return best
	}
	if v4 := parsed.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: parsed.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// firstUsable is the .1 convention: the address a home router almost always
// takes. Used only as a fallback, and only for a host that actually answered.
func firstUsable(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	v4 := n.IP.To4()
	if v4 == nil {
		return ""
	}
	if ones, bits := n.Mask.Size(); bits-ones < 2 {
		return "" // /31 and /32 have no router convention to appeal to
	}
	next := make(net.IP, len(v4))
	copy(next, v4)
	next[3]++
	return next.String()
}

func worstByHost(findings []model.Finding) map[string]model.Severity {
	worst := map[string]model.Severity{}
	for _, f := range findings {
		if f.Severity.Rank() > worst[f.Host].Rank() {
			worst[f.Host] = f.Severity
		}
	}
	return worst
}

func worstIn(hosts []model.Host, worst map[string]model.Severity) model.Severity {
	out := model.Severity("")
	for _, h := range hosts {
		if worst[h.IP].Rank() > out.Rank() {
			out = worst[h.IP]
		}
	}
	return out
}

func openCount(h model.Host) int {
	n := 0
	for _, s := range h.Services {
		if s.State == model.StateOpen {
			n++
		}
	}
	return n
}

func labelFor(ip string, names map[string]string) string {
	if n, ok := names[ip]; ok && n != "" {
		return n
	}
	return ip
}

func stringSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, s := range items {
		set[s] = true
	}
	return set
}

// lessIP orders addresses numerically, so .9 sorts before .10.
func lessIP(a, b string) bool {
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

// LocalAddresses lists this machine's own non-loopback addresses, for the "you
// are here" marker. A failure here is not worth failing a run over: the map
// simply doesn't mark a local host.
func LocalAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			out = append(out, ipnet.IP.String())
		}
	}
	return out
}
