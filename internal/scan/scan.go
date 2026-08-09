// Package scan is the thin bridge that wires the pipeline together:
// capture → dissect → registry. Every consumer of live packets (the wizard's
// initial sweep, `watch`, and the daemon) feeds frames through one Scanner so
// the observe-and-identify logic lives in exactly one place.
package scan

import (
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/dissect"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
)

// Default timings for MAC-conflict (ARP-spoof) detection.
const (
	defaultConflictWindow   = 2 * time.Minute  // "previous owner still active" horizon
	defaultConflictCooldown = 10 * time.Minute // per-IP mute so a spoof storm alerts once
)

// ipBinding records which MAC last claimed an IP, and when.
type ipBinding struct {
	mac  string
	seen time.Time
}

// Conflict describes an IP that has moved to a different MAC while its previous
// owner was still active — the passive tell of ARP spoofing / a MAC-IP clash.
type Conflict struct {
	IP     string
	OldMAC string
	NewMAC string
	Old    *model.Device // previous owner, if we know it (may be nil)
	New    *model.Device // new claimant; filled in by Handle after Observe
}

// Scanner dissects frames and folds them into a registry, notifying callers of
// newly-appeared and updated devices.
type Scanner struct {
	reg *registry.Registry
	now func() time.Time

	conflictWindow   time.Duration
	conflictCooldown time.Duration
	bindings         map[string]ipBinding // IP -> current owner
	conflictAlerted  map[string]time.Time // IP -> last conflict alert

	// OnNew fires the first time a MAC is ever observed this session.
	OnNew func(*model.Device)
	// OnSeen fires for every observation of an already-known MAC.
	OnSeen func(*model.Device)
	// OnDHCPServer fires once when a device that is NOT in the trusted baseline
	// is first seen handing out DHCP leases — the rogue-DHCP signal. It takes
	// precedence over OnNew for that packet: a rogue DHCP server is a scarier
	// event than a plain new device, and we don't want to alert twice.
	OnDHCPServer func(*model.Device)
	// OnConflict fires when an IP is claimed by a new MAC while the previous
	// owner is still active. Like OnDHCPServer it preempts OnNew/OnSeen for that
	// packet — a hijacked address outranks a plain appearance.
	OnConflict func(Conflict)
}

// New builds a Scanner over reg. If now is nil, time.Now is used.
func New(reg *registry.Registry, now func() time.Time) *Scanner {
	if now == nil {
		now = time.Now
	}
	return &Scanner{
		reg:              reg,
		now:              now,
		conflictWindow:   defaultConflictWindow,
		conflictCooldown: defaultConflictCooldown,
		bindings:         map[string]ipBinding{},
		conflictAlerted:  map[string]time.Time{},
	}
}

// Handle processes one raw frame. It is safe to pass anything — non-matching
// or malformed frames are simply ignored.
func (s *Scanner) Handle(data []byte) {
	obs, ok := dissect.Frame(data)
	if !ok {
		return
	}
	// Capture whether we already knew this MAC as a DHCP server, before Observe
	// mutates the record, so we can fire the rogue alert only on the transition.
	var wasServer bool
	if obs.DHCPServer {
		if prev, ok := s.reg.Get(obs.MAC); ok {
			wasServer = prev.DHCPServer
		}
	}
	// Check for an IP that just changed owner (ARP-spoof signal) before Observe
	// updates device IPs. This also refreshes the IP->MAC binding table.
	conflict := s.checkConflict(obs)

	dev, isNew := s.reg.Observe(obs, s.now())
	if dev == nil {
		return
	}
	if obs.DHCPServer && !wasServer && !dev.Known {
		if s.OnDHCPServer != nil {
			s.OnDHCPServer(dev)
		}
		return
	}
	if conflict != nil {
		conflict.New = dev
		if s.OnConflict != nil {
			s.OnConflict(*conflict)
		}
		return
	}
	if isNew {
		if s.OnNew != nil {
			s.OnNew(dev)
		}
		return
	}
	if s.OnSeen != nil {
		s.OnSeen(dev)
	}
}

// checkConflict maintains the IP->MAC binding table and reports a conflict when
// an IP is claimed by a different MAC than the one that held it moments ago.
//
// The window is the crux of avoiding false positives: DHCP legitimately reuses
// an address, but only after the old device has gone quiet. A *concurrent*
// second claimant — the previous owner seen within conflictWindow — is the tell
// of spoofing. A per-IP cooldown then keeps a spoof storm to a single alert.
func (s *Scanner) checkConflict(obs model.Observation) *Conflict {
	if obs.IP == "" || obs.MAC == "" {
		return nil
	}
	now := s.now()
	prev, had := s.bindings[obs.IP]
	s.bindings[obs.IP] = ipBinding{mac: obs.MAC, seen: now}

	if !had || prev.mac == obs.MAC {
		return nil
	}
	if now.Sub(prev.seen) > s.conflictWindow {
		return nil // old owner long gone — legitimate reassignment, not a clash
	}
	if last, ok := s.conflictAlerted[obs.IP]; ok && now.Sub(last) < s.conflictCooldown {
		return nil
	}
	s.conflictAlerted[obs.IP] = now
	old, _ := s.reg.Get(prev.mac)
	return &Conflict{IP: obs.IP, OldMAC: prev.mac, NewMAC: obs.MAC, Old: old}
}
