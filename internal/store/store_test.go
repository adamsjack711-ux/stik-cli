package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "devices.json"))
}

func TestFirstRunReportedWhenMissing(t *testing.T) {
	snap, err := tempStore(t).Load()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.FirstRun {
		t.Error("a missing store file should be reported as FirstRun")
	}
	if len(snap.Devices) != 0 {
		t.Error("first run should have no devices")
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	s := tempStore(t)
	in := []*model.Device{
		{MAC: "a4:83:e7:00:00:01", Name: "my phone", Known: true, FirstSeen: time.Unix(1000, 0).UTC(), LastSeen: time.Unix(2000, 0).UTC()},
		{MAC: "fc:65:de:00:00:02", Vendor: "Amazon", Known: false},
	}
	if err := s.Save(in); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snap.FirstRun {
		t.Error("store now exists; should not be FirstRun")
	}
	if len(snap.Devices) != 2 {
		t.Fatalf("round-tripped %d devices, want 2", len(snap.Devices))
	}
	if snap.Devices[0].Name != "my phone" || !snap.Devices[0].Known {
		t.Errorf("device 0 corrupted on round-trip: %+v", snap.Devices[0])
	}
}

func TestSaveIsAtomicNoTempLeftBehind(t *testing.T) {
	s := tempStore(t)
	if err := s.Save([]*model.Device{{MAC: "a4:83:e7:00:00:01"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(s.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("atomic write left a temp file behind: %s", e.Name())
		}
	}
	// Exactly one file — the target — should exist.
	if len(entries) != 1 || entries[0].Name() != filepath.Base(s.Path) {
		t.Errorf("unexpected files in store dir: %v", names(entries))
	}
}

func TestSavedFileIsValidJSON(t *testing.T) {
	s := tempStore(t)
	if err := s.Save([]*model.Device{{MAC: "a4:83:e7:00:00:01"}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("saved file is not valid JSON: %v", err)
	}
	if f.Version != schemaVersion {
		t.Errorf("version = %d, want %d", f.Version, schemaVersion)
	}
}

func TestCorruptFileRecoveredAndBackedUp(t *testing.T) {
	s := tempStore(t)
	if err := os.WriteFile(s.Path, []byte("{ this is not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var warned string
	s.Warn = func(msg string) { warned = msg }

	snap, err := s.Load()
	if err != nil {
		t.Fatalf("corrupt file should recover, not error: %v", err)
	}
	if !snap.Recovered {
		t.Error("expected Recovered = true")
	}
	if len(snap.Devices) != 0 {
		t.Error("recovery should start from an empty registry")
	}
	if warned == "" {
		t.Error("expected a warning about the corrupt file")
	}

	// The original bytes must be preserved in a .bak, not discarded.
	backups, _ := filepath.Glob(s.Path + ".corrupt-*.bak")
	if len(backups) != 1 {
		t.Fatalf("expected exactly one backup, found %d", len(backups))
	}
	got, _ := os.ReadFile(backups[0])
	if string(got) != "{ this is not valid json" {
		t.Errorf("backup did not preserve original bytes: %q", got)
	}
}

func TestEmptyDeviceListRoundTrips(t *testing.T) {
	s := tempStore(t)
	if err := s.Save(nil); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snap.FirstRun || snap.Recovered {
		t.Error("a saved empty list is a real, valid store — not first-run or corrupt")
	}
}

func names(entries []os.DirEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
