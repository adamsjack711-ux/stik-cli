package model

// NodeKind is what a node represents on the map.
type NodeKind string

const (
	KindSubnet   NodeKind = "subnet"    // a CIDR the scan covered
	KindGateway  NodeKind = "gateway"   // router / DHCP server for its subnet
	KindHost     NodeKind = "host"      // an ordinary scanned host
	KindThisHost NodeKind = "this-host" // the machine stik-net ran on: "you are here"
)

// EdgeEvidence records WHY an edge exists. The map is only honest if it
// distinguishes what was observed from what was inferred, so every edge carries
// the reason it was drawn.
type EdgeEvidence string

const (
	EvSameSubnet EdgeEvidence = "same-subnet" // L3 adjacency, not proof of an L2 link
	EvDHCP       EdgeEvidence = "dhcp"        // this host was seen handing out leases
	EvARP        EdgeEvidence = "arp"         // the passive watcher holds its MAC↔IP pairing
	EvGateway    EdgeEvidence = "gateway"     // inferred router position for the subnet
	EvLocal      EdgeEvidence = "local"       // the interface stik-net itself sits on
)

// NodeChange marks how a node differs from the run being compared against. It
// is empty on an ordinary map — only a diff sets it.
type NodeChange string

const (
	ChangeAdded   NodeChange = "added"   // present now, absent before
	ChangeRemoved NodeChange = "removed" // present before, gone now
	ChangeWorse   NodeChange = "worse"   // still here, worst finding got worse
	ChangeBetter  NodeChange = "better"  // still here, worst finding improved
)

// Node is one thing on the map.
type Node struct {
	ID     string   `json:"id"` // IP, or the CIDR for a subnet node
	Kind   NodeKind `json:"kind"`
	Label  string   `json:"label"`         // device name from the registry, else the IP
	Subnet string   `json:"subnet"`        // CIDR it sits in
	Sev    Severity `json:"sev"`           // worst finding on the node → colour
	Open   int      `json:"open"`          // open services → size
	MAC    string   `json:"mac,omitempty"` // when the passive registry knows it

	// These three are set only on a diffed map, where they drive highlighting.
	Change   NodeChange `json:"change,omitempty"`
	PrevSev  Severity   `json:"prev_sev,omitempty"`  // severity in the earlier run
	PrevOpen int        `json:"prev_open,omitempty"` // open services in the earlier run
}

// Edge is a relationship between two nodes. Inferred marks the ones stik-net
// reasoned its way to rather than watched happen — drawn dashed, and never
// described as if it were observed.
type Edge struct {
	From     string       `json:"from"`
	To       string       `json:"to"`
	Evidence EdgeEvidence `json:"evidence"`
	Inferred bool         `json:"inferred"`

	// Change is set only on a diffed map.
	Change NodeChange `json:"change,omitempty"`
}

// Graph is the inferred picture of the network: nodes, why they're connected,
// and where the map starts reading from.
type Graph struct {
	Nodes []Node   `json:"nodes"`
	Edges []Edge   `json:"edges"`
	Roots []string `json:"roots"` // gateways / entry points
}

// NodeByID finds a node, reporting whether it exists.
func (g Graph) NodeByID(id string) (Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// Empty reports whether there is nothing to draw.
func (g Graph) Empty() bool { return len(g.Nodes) == 0 }
