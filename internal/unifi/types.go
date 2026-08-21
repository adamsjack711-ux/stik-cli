package unifi

import "context"

// The classic private API is where the segmentation detail lives. The newer
// official Integration API exposes only sites, clients and devices — no network
// configuration, no firewall — so a map built on it would be a list of names
// with no structure. These types follow the classic shapes.

// Network is one configured network / VLAN.
type Network struct {
	ID        string `json:"_id"`
	Name      string `json:"name"`
	Purpose   string `json:"purpose"` // corporate | guest | wan | vlan-only | remote-user-vpn
	VLAN      any    `json:"vlan"`    // string or number depending on controller version
	Subnet    string `json:"ip_subnet"`
	Enabled   *bool  `json:"enabled"`
	DHCPOn    bool   `json:"dhcpd_enabled"`
	DHCPStart string `json:"dhcpd_start"`
	DHCPStop  string `json:"dhcpd_stop"`

	// UniFi has spelled isolation two ways across versions, and either counts:
	// missing it on one firmware would report a walled-off network as open.
	Isolation    bool `json:"network_isolation_enabled"`
	IsolationAlt bool `json:"isolation"`

	// IsGuest marks a guest network. It is NOT an isolation flag, and treating
	// it as one would report an open guest network as walled off — an error in
	// the direction that gets someone hurt. A guest network is isolated only if
	// it actually says so above.
	IsGuest bool `json:"is_guest"`
}

// IsGuestNetwork reports whether this carries guests, by purpose or by flag.
func (n Network) IsGuestNetwork() bool { return n.Purpose == "guest" || n.IsGuest }

// Isolated reports whether this network is walled off from the others, however
// the controller happens to spell it.
func (n Network) Isolated() bool {
	return n.Isolation || n.IsolationAlt
}

// Infra is a gateway, switch or access point.
type Infra struct {
	MAC     string `json:"mac"`
	Name    string `json:"name"`
	Model   string `json:"model"`
	Type    string `json:"type"` // ugw | usw | uap | udm
	Version string `json:"version"`
	Adopted bool   `json:"adopted"`
	State   int    `json:"state"` // 1 = connected
}

// Station is a connected client.
type Station struct {
	MAC        string `json:"mac"`
	Hostname   string `json:"hostname"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	NetworkID  string `json:"network_id"`
	Network    string `json:"network"`
	IsWired    bool   `json:"is_wired"`
	IsGuest    bool   `json:"is_guest"`
	Authorized bool   `json:"authorized"`
	OUI        string `json:"oui"`
	Uptime     int64  `json:"uptime"`
}

// Display is the best human name for a station.
func (s Station) Display() string {
	switch {
	case s.Name != "":
		return s.Name
	case s.Hostname != "":
		return s.Hostname
	case s.OUI != "":
		return s.OUI + " device"
	default:
		return "unnamed device"
	}
}

// FirewallRule is the legacy rule shape. Newer controllers moved to a
// zone-based firewall whose policy matrix has no read API, so this is fetched
// best-effort and its absence is reported rather than hidden.
type FirewallRule struct {
	ID       string `json:"_id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Action   string `json:"action"`  // accept | drop | reject
	Ruleset  string `json:"ruleset"` // LAN_IN, GUEST_IN, …
	SrcName  string `json:"src_firewallgroup_ids_name"`
	DstName  string `json:"dst_firewallgroup_ids_name"`
	Index    int    `json:"rule_index"`
	Logging  bool   `json:"logging"`
	Protocol string `json:"protocol"`
}

// Snapshot is everything the map is built from.
type Snapshot struct {
	Networks   []Network
	Infra      []Infra
	Stations   []Station
	Firewall   []FirewallRule
	FirewallOK bool // false when the controller would not serve the legacy rules
}

// Fetch reads the whole picture in one pass.
func (c *Client) Fetch(ctx context.Context) (Snapshot, error) {
	var snap Snapshot

	if err := c.get(ctx, "rest/networkconf", &snap.Networks); err != nil {
		return snap, err
	}
	if err := c.get(ctx, "stat/device", &snap.Infra); err != nil {
		return snap, err
	}
	if err := c.get(ctx, "stat/sta", &snap.Stations); err != nil {
		return snap, err
	}

	// Best-effort: a zone-based-firewall controller simply will not serve these.
	if err := c.optional(ctx, "rest/firewallrule", &snap.Firewall); err != nil {
		return snap, err
	}
	snap.FirewallOK = len(snap.Firewall) > 0

	return snap, nil
}
