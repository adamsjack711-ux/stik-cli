package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
)

func plainStyle() Style { return Style{color: false} }

func seedRegistry(macs ...string) (*registry.Registry, []*model.Device) {
	r := registry.New(nil)
	now := time.Now()
	for _, m := range macs {
		r.Observe(model.Observation{MAC: m}, now)
	}
	return r, r.SortedByLastSeen()
}

func TestWizardNamesAndAccepts(t *testing.T) {
	r, devices := seedRegistry("a4:83:e7:00:00:01")
	// "y" then a name.
	in := strings.NewReader("y\nmy phone\n")
	var out strings.Builder

	res := RunWizard(in, &out, plainStyle(), r, devices)
	if res.Named != 1 {
		t.Errorf("Named = %d, want 1", res.Named)
	}
	dev, _ := r.Get("a4:83:e7:00:00:01")
	if dev.Name != "my phone" || !dev.Known {
		t.Errorf("device not named/accepted: %+v", dev)
	}
	if len(r.Unknown()) != 0 {
		t.Error("named device should be part of the baseline")
	}
}

func TestWizardDefaultAnswerIsYes(t *testing.T) {
	r, devices := seedRegistry("a4:83:e7:00:00:01")
	// Empty answer (just Enter) means yes; empty name falls back to hostname.
	in := strings.NewReader("\n\n")
	var out strings.Builder
	res := RunWizard(in, &out, plainStyle(), r, devices)
	if res.Named != 1 {
		t.Errorf("Named = %d, want 1 (empty answer defaults to yes)", res.Named)
	}
}

func TestWizardSkipLeavesDeviceUnknown(t *testing.T) {
	r, devices := seedRegistry("a4:83:e7:00:00:01")
	in := strings.NewReader("skip\n")
	var out strings.Builder
	res := RunWizard(in, &out, plainStyle(), r, devices)
	if res.Deferred != 1 {
		t.Errorf("Deferred = %d, want 1", res.Deferred)
	}
	if len(r.Unknown()) != 1 {
		t.Error("a skipped device must remain unknown (still gets flagged later)")
	}
}

func TestWizardNoAcknowledgesWithoutName(t *testing.T) {
	r, devices := seedRegistry("a4:83:e7:00:00:01")
	in := strings.NewReader("n\n")
	var out strings.Builder
	res := RunWizard(in, &out, plainStyle(), r, devices)
	if res.Acked != 1 {
		t.Errorf("Acked = %d, want 1", res.Acked)
	}
	dev, _ := r.Get("a4:83:e7:00:00:01")
	if !dev.Known || dev.Name != "" {
		t.Errorf("'n' should mark known without a name: %+v", dev)
	}
}

func TestWizardStopsOnEOF(t *testing.T) {
	// Two devices, but input ends after the first answer — must not hang or panic.
	r, devices := seedRegistry("a4:83:e7:00:00:01", "fc:65:de:00:00:02")
	in := strings.NewReader("y\nphone\n") // nothing for the second device
	var out strings.Builder
	res := RunWizard(in, &out, plainStyle(), r, devices)
	if res.Named != 1 {
		t.Errorf("Named = %d, want 1 before EOF", res.Named)
	}
}
