package registry

import (
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

func obs(mac string) model.Observation {
	return model.Observation{MAC: mac, Source: model.SourceARP}
}

func TestFirstSightIsNew(t *testing.T) {
	r := New(nil)
	_, isNew := r.Observe(obs("a4:83:e7:00:00:01"), time.Now())
	if !isNew {
		t.Error("a never-before-seen MAC must be reported as new")
	}
}

func TestSecondSightIsNotNew(t *testing.T) {
	r := New(nil)
	now := time.Now()
	r.Observe(obs("a4:83:e7:00:00:01"), now)
	_, isNew := r.Observe(obs("a4:83:e7:00:00:01"), now.Add(time.Second))
	if isNew {
		t.Error("a repeat sighting must not be reported as new")
	}
}

func TestBaselineDeviceIsNotNew(t *testing.T) {
	// A device loaded from the stored baseline must never be flagged new.
	base := []*model.Device{{MAC: "a4:83:e7:00:00:01", Known: true, FirstSeen: time.Now()}}
	r := New(base)
	_, isNew := r.Observe(obs("a4:83:e7:00:00:01"), time.Now())
	if isNew {
		t.Error("a device already in the baseline must not be new")
	}
}

func TestForgottenDeviceIsNewAgain(t *testing.T) {
	r := New([]*model.Device{{MAC: "a4:83:e7:00:00:01", Known: true}})
	if !r.Forget("a4:83:e7:00:00:01") {
		t.Fatal("forget should succeed for a known device")
	}
	_, isNew := r.Observe(obs("a4:83:e7:00:00:01"), time.Now())
	if !isNew {
		t.Error("a forgotten device must be treated as new when it returns")
	}
}

func TestFirstSeenIsStable(t *testing.T) {
	r := New(nil)
	t0 := time.Now()
	dev, _ := r.Observe(obs("a4:83:e7:00:00:01"), t0)
	first := dev.FirstSeen
	dev2, _ := r.Observe(obs("a4:83:e7:00:00:01"), t0.Add(time.Hour))
	if !dev2.FirstSeen.Equal(first) {
		t.Errorf("FirstSeen changed: %v -> %v", first, dev2.FirstSeen)
	}
	if !dev2.LastSeen.After(first) {
		t.Error("LastSeen should advance on a later sighting")
	}
}

func TestObserveMergesFactsAndIdentifies(t *testing.T) {
	r := New(nil)
	now := time.Now()
	// First heard via ARP (MAC + IP only).
	r.Observe(model.Observation{MAC: "a4:83:e7:00:00:01", IP: "192.168.1.10", Source: model.SourceARP}, now)
	// Later, mDNS reveals the hostname.
	dev, _ := r.Observe(model.Observation{MAC: "a4:83:e7:00:00:01", Hostname: "dylans-iphone", Source: model.SourceMDNS}, now)
	if dev.IP != "192.168.1.10" {
		t.Errorf("IP not retained across observations: %q", dev.IP)
	}
	if dev.Hostname != "dylans-iphone" {
		t.Errorf("hostname not merged: %q", dev.Hostname)
	}
	if dev.Label != "Apple iPhone" {
		t.Errorf("label = %q, want 'Apple iPhone' after merge", dev.Label)
	}
}

func TestAcceptMarksKnownAndNames(t *testing.T) {
	r := New(nil)
	r.Observe(obs("a4:83:e7:00:00:01"), time.Now())
	if len(r.Unknown()) != 1 {
		t.Fatalf("expected 1 unknown device, got %d", len(r.Unknown()))
	}
	r.Accept("a4:83:e7:00:00:01", "my phone")
	if len(r.Unknown()) != 0 {
		t.Error("accepted device should no longer be unknown")
	}
	dev, _ := r.Get("a4:83:e7:00:00:01")
	if dev.Name != "my phone" || !dev.Known {
		t.Errorf("accept did not set name/known: %+v", dev)
	}
}

func TestFindByHostnameAndMAC(t *testing.T) {
	r := New(nil)
	r.Observe(model.Observation{MAC: "a4:83:e7:00:00:01", Hostname: "dylans-iphone", IP: "192.168.1.10"}, time.Now())
	if got := r.Find("dylan"); len(got) != 1 {
		t.Errorf("substring hostname find returned %d matches", len(got))
	}
	if got := r.Find("192.168.1.10"); len(got) != 1 {
		t.Errorf("exact IP find returned %d matches", len(got))
	}
	if got := r.Find("A4:83:E7:00:00:01"); len(got) != 1 {
		t.Errorf("case-insensitive MAC find returned %d matches", len(got))
	}
	if got := r.Find("nothing"); len(got) != 0 {
		t.Errorf("bogus query matched %d", len(got))
	}
}

func TestEmptyObservationIgnored(t *testing.T) {
	r := New(nil)
	dev, isNew := r.Observe(model.Observation{MAC: ""}, time.Now())
	if dev != nil || isNew {
		t.Error("an observation with no MAC must be ignored")
	}
}
