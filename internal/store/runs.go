package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Runs are saved audit results, kept beside the device registry. They exist so
// the map can be redrawn — or a report re-read — without scanning again: the
// quietest scan is the one you don't repeat.
//
// The payload is opaque here on purpose. store stays the only package that
// touches disk; it does not need to know what an audit report contains.

// RunInfo describes one saved run.
type RunInfo struct {
	Path string
	When time.Time
	Size int64
}

// RunsDir is where saved runs live: alongside the registry, in runs/.
func (s *Store) RunsDir() string { return filepath.Join(filepath.Dir(s.Path), "runs") }

// SaveRun writes a run atomically and returns its path. Runs are named by their
// timestamp so they sort chronologically in a directory listing.
func (s *Store) SaveRun(data []byte) (string, error) {
	dir := s.RunsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	path := filepath.Join(dir, "run-"+s.clock().UTC().Format("20060102-150405")+".json")

	tmp, err := os.CreateTemp(dir, ".run-*.tmp")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("saving run: %w", err)
	}
	return path, nil
}

// ListRuns returns saved runs, newest first.
func (s *Store) ListRuns() ([]RunInfo, error) {
	entries, err := os.ReadDir(s.RunsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.RunsDir(), err)
	}
	var runs []RunInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "run-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		runs = append(runs, RunInfo{
			Path: filepath.Join(s.RunsDir(), e.Name()),
			When: info.ModTime(),
			Size: info.Size(),
		})
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Path > runs[j].Path })
	return runs, nil
}

// LoadRun reads a saved run. ref is a file path, or "last"/"latest" for the
// most recent one.
func (s *Store) LoadRun(ref string) ([]byte, string, error) {
	path := ref
	if ref == "" || ref == "last" || ref == "latest" {
		runs, err := s.ListRuns()
		if err != nil {
			return nil, "", err
		}
		if len(runs) == 0 {
			return nil, "", fmt.Errorf("no saved runs in %s — run `stik-net audit --scope <file>` first", s.RunsDir())
		}
		path = runs[0].Path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading run %s: %w", path, err)
	}
	return data, path, nil
}
