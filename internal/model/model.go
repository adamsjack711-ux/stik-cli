// Package model holds the plain data types that flow through stik's pipeline:
// Observation (one fact from one packet), Identity (the human reading of a
// device), and Device (the persisted registry record).
package model

import "time"

// Source names the broadcast/multicast protocol an observation came from.
type Source string

const (
	SourceARP  Source = "arp"
	SourceMDNS Source = "mdns"
	SourceDHCP Source = "dhcp"
)

// Observation is a single fact learned from one broadcast/multicast packet.
// Fields the packet did not reveal are left empty; the registry merges
// successive observations of the same MAC into one Device.
type Observation struct {
	MAC             string // normalized "aa:bb:cc:dd:ee:ff"
	IP              string // "" if this packet did not reveal one
	Hostname        string // "" unless mDNS/DHCP announced a name
	DHCPFingerprint string // DHCP requested-option codes in order, "" if none
	DHCPVendorClass string // DHCP option 60, e.g. "android-dhcp-14"; "" if none
	DHCPServer      bool   // this packet was a DHCP OFFER/ACK — MAC is a server handing out leases
	Source          Source
}

// Identity is the human reading of a device: what to call it and why.
type Identity struct {
	Vendor  string // manufacturer from the OUI table, "" if unknown/private
	Private bool   // locally-administered (randomized) MAC — vendor is meaningless
	Label   string // the sentence shown to a person: "Apple iPhone"
	Reason  string // one plain sentence of justification, for --verbose and alerts
}

// Device is the persisted registry record — the baseline of "normal".
type Device struct {
	MAC             string    `json:"mac"`
	Name            string    `json:"name,omitempty"`  // user-given, from the wizard or `stik name`
	Label           string    `json:"label,omitempty"` // derived identity sentence at first sight
	Vendor          string    `json:"vendor,omitempty"`
	Hostname        string    `json:"hostname,omitempty"`
	IP              string    `json:"ip,omitempty"`
	DHCPFingerprint string    `json:"dhcp_fingerprint,omitempty"`
	DHCPVendorClass string    `json:"dhcp_vendor_class,omitempty"`
	Private         bool      `json:"private,omitempty"`     // randomized MAC
	DHCPServer      bool      `json:"dhcp_server,omitempty"` // seen handing out DHCP leases
	Known           bool      `json:"known"`                 // reviewed & accepted into the baseline
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// Display returns the best human name for a device: the user-given name if
// there is one, otherwise the derived identity label, otherwise a bare hint.
func (d *Device) Display() string {
	switch {
	case d.Name != "":
		return d.Name
	case d.Label != "":
		return d.Label
	default:
		return "unnamed device"
	}
}
