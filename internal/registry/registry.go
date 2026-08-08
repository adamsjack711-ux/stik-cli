// Package registry holds the set of devices stik knows about and implements
// the trust-on-first-use model: the baseline is whatever was present when the
// user first ran the wizard; anything appearing afterwards that isn't in the
// baseline is "new" — and new is the entire point of the tool.
//
// The registry is pure in-memory logic. It never touches disk; the store loads
// devices into it and saves the slice back out.
package registry

import (
	"sort"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/identify"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Registry is an in-memory view of known devices, keyed by MAC.
type Registry struct {
	byMAC map[string]*model.Device
	order []string // MACs in first-seen order, for stable listing
}

// New builds a registry from previously stored devices (may be nil).
func New(devices []*model.Device) *Registry {
	r := &Registry{byMAC: make(map[string]*model.Device, len(devices))}
	for _, d := range devices {
		if d == nil || d.MAC == "" {
			continue
		}
		if _, dup := r.byMAC[d.MAC]; dup {
			continue
		}
		r.byMAC[d.MAC] = d
		r.order = append(r.order, d.MAC)
	}
	return r
}

// Devices returns every known device in first-seen order.
func (r *Registry) Devices() []*model.Device {
	out := make([]*model.Device, 0, len(r.order))
	for _, mac := range r.order {
		out = append(out, r.byMAC[mac])
	}
	return out
}

// Get returns the device for a MAC, if known.
func (r *Registry) Get(mac string) (*model.Device, bool) {
	d, ok := r.byMAC[strings.ToLower(mac)]
	return d, ok
}

// Observe folds one observation into the registry, creating or updating a
// device and re-deriving its identity from everything learned so far. The
// boolean is true when this MAC had never been seen before — the signal a
// watcher uses to decide whether to raise an alert.
func (r *Registry) Observe(obs model.Observation, now time.Time) (*model.Device, bool) {
	if obs.MAC == "" {
		return nil, false
	}
	dev, seen := r.byMAC[obs.MAC]
	if !seen {
		dev = &model.Device{MAC: obs.MAC, FirstSeen: now}
		r.byMAC[obs.MAC] = dev
		r.order = append(r.order, obs.MAC)
	}
	dev.LastSeen = now

	if obs.IP != "" {
		dev.IP = obs.IP
	}
	if obs.Hostname != "" {
		dev.Hostname = obs.Hostname
	}
	if obs.DHCPFingerprint != "" {
		dev.DHCPFingerprint = obs.DHCPFingerprint
	}
	if obs.DHCPVendorClass != "" {
		dev.DHCPVendorClass = obs.DHCPVendorClass
	}
	if obs.DHCPServer {
		dev.DHCPServer = true
	}

	id := identify.Identify(identify.Input{
		MAC:             dev.MAC,
		Hostname:        dev.Hostname,
		DHCPFingerprint: dev.DHCPFingerprint,
		DHCPVendorClass: dev.DHCPVendorClass,
	})
	dev.Vendor = id.Vendor
	dev.Private = id.Private
	dev.Label = id.Label

	return dev, !seen
}

// Unknown returns devices that have been seen but not yet accepted into the
// baseline (Known == false) — i.e. the ones worth surfacing to the user.
func (r *Registry) Unknown() []*model.Device {
	var out []*model.Device
	for _, mac := range r.order {
		if d := r.byMAC[mac]; !d.Known {
			out = append(out, d)
		}
	}
	return out
}

// Accept marks a device as part of the trusted baseline, optionally naming it.
func (r *Registry) Accept(mac, name string) bool {
	d, ok := r.byMAC[strings.ToLower(mac)]
	if !ok {
		return false
	}
	d.Known = true
	if name != "" {
		d.Name = name
	}
	return true
}

// Forget removes a device entirely. It will be treated as new if seen again.
func (r *Registry) Forget(mac string) bool {
	mac = strings.ToLower(mac)
	if _, ok := r.byMAC[mac]; !ok {
		return false
	}
	delete(r.byMAC, mac)
	for i, m := range r.order {
		if m == mac {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	return true
}

// Find resolves a user-typed reference to devices. It matches a MAC or IP
// exactly, otherwise a case-insensitive substring of the name, hostname, or
// label. Returning all matches lets the caller report ambiguity clearly.
func (r *Registry) Find(query string) []*model.Device {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var exact, partial []*model.Device
	for _, mac := range r.order {
		d := r.byMAC[mac]
		if strings.ToLower(d.MAC) == q || strings.ToLower(d.IP) == q {
			exact = append(exact, d)
			continue
		}
		hay := strings.ToLower(strings.Join([]string{d.Name, d.Hostname, d.Label}, "\n"))
		if q != "" && strings.Contains(hay, q) {
			partial = append(partial, d)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return partial
}

// SortedByLastSeen returns devices most-recently-seen first (for the live view).
func (r *Registry) SortedByLastSeen() []*model.Device {
	out := r.Devices()
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}
