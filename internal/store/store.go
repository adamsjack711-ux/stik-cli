// Package store is the ONE place in stik that touches the device file on disk.
// No other package reads or writes it. The exported surface (Load/Save/Path)
// is deliberately tiny so a different backend — SQLite, say — could replace it
// without any command changing.
//
// Durability model: writes are atomic (write a sibling temp file, then rename
// over the target), so a crash or a second stik process can never leave a
// half-written, unparseable store behind.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

const schemaVersion = 1

// Store persists the device registry to a single JSON file.
type Store struct {
	Path string
	// Warn receives a human-readable message when a corrupt file is recovered.
	// nil is fine — recovery still happens, silently.
	Warn func(string)
	now  func() time.Time
}

// Snapshot is the result of loading the store.
type Snapshot struct {
	Devices   []*model.Device
	FirstRun  bool // the store file did not exist — trigger the naming wizard
	Recovered bool // the file was corrupt; it was backed up and reset
}

type fileFormat struct {
	Version int             `json:"version"`
	Devices []*model.Device `json:"devices"`
}

// DefaultPath is ~/.stik/devices.json, or $STIK_HOME/devices.json if set.
func DefaultPath() string {
	if home := os.Getenv("STIK_HOME"); home != "" {
		return filepath.Join(home, "devices.json")
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, ".stik", "devices.json")
}

// New returns a Store rooted at path.
func New(path string) *Store {
	return &Store{Path: path, now: time.Now}
}

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Load reads the registry. A missing file is not an error — it is first run.
// A corrupt file is not fatal either: it is backed up and the registry starts
// fresh, so a mangled store can never wedge the tool.
func (s *Store) Load() (Snapshot, error) {
	raw, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{Devices: nil, FirstRun: true}, nil
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("reading %s: %w", s.Path, err)
	}

	var f fileFormat
	if jsonErr := json.Unmarshal(raw, &f); jsonErr != nil {
		backup := fmt.Sprintf("%s.corrupt-%d.bak", s.Path, s.clock().UnixNano())
		if renameErr := os.Rename(s.Path, backup); renameErr != nil {
			s.warn(fmt.Sprintf("device store was unreadable and could not be backed up (%v) — starting fresh", renameErr))
		} else {
			s.warn(fmt.Sprintf("device store was unreadable — backed it up to %s and started fresh", backup))
		}
		return Snapshot{Devices: nil, Recovered: true}, nil
	}

	return Snapshot{Devices: f.Devices}, nil
}

// Save writes the registry atomically: a temp file in the same directory,
// then an atomic rename over the target.
func (s *Store) Save(devices []*model.Device) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(fileFormat{Version: schemaVersion, Devices: devices}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding registry: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".devices-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	// If anything below fails, don't leave the temp file lying around.
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("replacing %s: %w", s.Path, err)
	}
	return nil
}

func (s *Store) warn(msg string) {
	if s.Warn != nil {
		s.Warn(msg)
	}
}
