package topo

import (
	"sort"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Diffing two maps answers the question a re-audit is really asking: what
// appeared on my network, what left, and what got worse. The result is itself a
// graph — the union of both runs, with every node and edge marked — so the same
// renderers draw it and no second layout exists to drift out of sync.

// Delta is the union graph plus the counts worth stating in one line.
type Delta struct {
	Graph   model.Graph
	Added   []model.Node
	Removed []model.Node
	Worse   []model.Node
	Better  []model.Node
}

// Empty reports whether the two maps are the same shape with the same severities.
func (d Delta) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Worse) == 0 && len(d.Better) == 0
}

// DiffGraphs builds the union map. A node in both runs keeps its current state
// and gains a marker if its worst finding moved; a node in only one run is
// marked added or removed, and a removed one is carried over from the earlier
// map so the picture still shows where it used to sit.
func DiffGraphs(before, after model.Graph) Delta {
	beforeNodes := indexNodes(before)
	afterNodes := indexNodes(after)

	var d Delta
	for _, n := range after.Nodes {
		prev, existed := beforeNodes[n.ID]
		node := n
		switch {
		case !existed:
			node.Change = model.ChangeAdded
			d.Added = append(d.Added, node)
		case n.Sev.Rank() > prev.Sev.Rank():
			node.Change = model.ChangeWorse
			node.PrevSev, node.PrevOpen = prev.Sev, prev.Open
			// A subnet's severity is a roll-up of its hosts, so it moves whenever
			// one of them does. Colour it, but don't count it: the host inside is
			// the event, and counting both reports one change twice.
			if n.Kind != model.KindSubnet {
				d.Worse = append(d.Worse, node)
			}
		case n.Sev.Rank() < prev.Sev.Rank():
			node.Change = model.ChangeBetter
			node.PrevSev, node.PrevOpen = prev.Sev, prev.Open
			if n.Kind != model.KindSubnet {
				d.Better = append(d.Better, node)
			}
		default:
			node.PrevOpen = prev.Open
		}
		d.Graph.Nodes = append(d.Graph.Nodes, node)
	}

	for _, n := range before.Nodes {
		if _, still := afterNodes[n.ID]; still {
			continue
		}
		node := n
		node.Change = model.ChangeRemoved
		node.PrevSev, node.PrevOpen = n.Sev, n.Open
		d.Removed = append(d.Removed, node)
		d.Graph.Nodes = append(d.Graph.Nodes, node)
	}

	d.Graph.Edges = diffEdges(before, after)
	d.Graph.Roots = after.Roots
	if len(d.Graph.Roots) == 0 {
		d.Graph.Roots = before.Roots
	}

	sortNodes(d.Graph.Nodes)
	sortNodes(d.Added)
	sortNodes(d.Removed)
	sortNodes(d.Worse)
	sortNodes(d.Better)
	return d
}

func diffEdges(before, after model.Graph) []model.Edge {
	type edgeKey struct{ from, to string }
	beforeEdges := map[edgeKey]model.Edge{}
	for _, e := range before.Edges {
		beforeEdges[edgeKey{e.From, e.To}] = e
	}
	seen := map[edgeKey]bool{}

	var out []model.Edge
	for _, e := range after.Edges {
		key := edgeKey{e.From, e.To}
		seen[key] = true
		edge := e
		if _, existed := beforeEdges[key]; !existed {
			edge.Change = model.ChangeAdded
		}
		out = append(out, edge)
	}
	for key, e := range beforeEdges {
		if seen[key] {
			continue
		}
		edge := e
		edge.Change = model.ChangeRemoved
		out = append(out, edge)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return model.LessIP(out[i].From, out[j].From)
		}
		return out[i].To < out[j].To
	})
	return out
}

func indexNodes(g model.Graph) map[string]model.Node {
	out := make(map[string]model.Node, len(g.Nodes))
	for _, n := range g.Nodes {
		out[n.ID] = n
	}
	return out
}

// sortNodes keeps subnets first, then hosts in numeric address order, so a
// diffed map reads in the same order as an ordinary one.
func sortNodes(nodes []model.Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if (a.Kind == model.KindSubnet) != (b.Kind == model.KindSubnet) {
			return a.Kind == model.KindSubnet
		}
		if a.Subnet != b.Subnet {
			return a.Subnet < b.Subnet
		}
		return model.LessIP(a.ID, b.ID)
	})
}
