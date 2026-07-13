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

// Scanner dissects frames and folds them into a registry, notifying callers of
// newly-appeared and updated devices.
type Scanner struct {
	reg *registry.Registry
	now func() time.Time

	// OnNew fires the first time a MAC is ever observed this session.
	OnNew func(*model.Device)
	// OnSeen fires for every observation of an already-known MAC.
	OnSeen func(*model.Device)
}

// New builds a Scanner over reg. If now is nil, time.Now is used.
func New(reg *registry.Registry, now func() time.Time) *Scanner {
	if now == nil {
		now = time.Now
	}
	return &Scanner{reg: reg, now: now}
}

// Handle processes one raw frame. It is safe to pass anything — non-matching
// or malformed frames are simply ignored.
func (s *Scanner) Handle(data []byte) {
	obs, ok := dissect.Frame(data)
	if !ok {
		return
	}
	dev, isNew := s.reg.Observe(obs, s.now())
	if dev == nil {
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
