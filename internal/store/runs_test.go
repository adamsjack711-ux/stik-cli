package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s := New(filepath.Join(t.TempDir(), "devices.json"))
	return s
}

func TestSaveAndLoadLatestRun(t *testing.T) {
	s := testStore(t)
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }

	if _, err := s.SaveRun([]byte(`{"run":1}`)); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	at = at.Add(time.Hour)
	second, err := s.SaveRun([]byte(`{"run":2}`))
	if err != nil {
		t.Fatalf("SaveRun: %v", err)
	}

	data, path, err := s.LoadRun("last")
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if string(data) != `{"run":2}` {
		t.Errorf("loaded %s, want the newest run", data)
	}
	if path != second {
		t.Errorf("loaded %s, want %s", path, second)
	}
}

func TestListRunsNewestFirstAndIgnoresStrays(t *testing.T) {
	s := testStore(t)
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	for i := 0; i < 3; i++ {
		if _, err := s.SaveRun([]byte(`{}`)); err != nil {
			t.Fatalf("SaveRun: %v", err)
		}
		at = at.Add(time.Minute)
	}
	// A stray file in the runs directory must not be offered as a run.
	if err := writeFile(filepath.Join(s.RunsDir(), "notes.txt"), "hello"); err != nil {
		t.Fatal(err)
	}

	runs, err := s.ListRuns()
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 3 {
		t.Fatalf("ListRuns = %d entries, want 3", len(runs))
	}
	if !(runs[0].Path > runs[1].Path && runs[1].Path > runs[2].Path) {
		t.Errorf("runs are not newest-first: %v", runs)
	}
}

func TestLoadRunWithNoRunsExplainsItself(t *testing.T) {
	s := testStore(t)
	_, _, err := s.LoadRun("last")
	if err == nil {
		t.Fatal("want an error when nothing has been saved")
	}
	if !strings.Contains(err.Error(), "stik-net audit") {
		t.Errorf("error should say how to make a run, got: %v", err)
	}
}

func TestLoadRunByPath(t *testing.T) {
	s := testStore(t)
	s.now = func() time.Time { return time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC) }
	path, err := s.SaveRun([]byte(`{"run":"explicit"}`))
	if err != nil {
		t.Fatalf("SaveRun: %v", err)
	}
	data, got, err := s.LoadRun(path)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if string(data) != `{"run":"explicit"}` || got != path {
		t.Errorf("LoadRun(%q) = %s / %s", path, data, got)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
