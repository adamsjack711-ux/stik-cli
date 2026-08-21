package cve

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Answers are cached on disk because every query tells a third party something
// about the network being audited. A nightly re-audit of an unchanged network
// should disclose nothing new, and a cache is what makes that true. It also
// keeps the scan inside NVD's rate limit, but that is the lesser reason.

const cacheTTL = 7 * 24 * time.Hour

// Cache is a directory of CPE → results, each entry stamped with when it was
// fetched.
type Cache struct {
	Dir string
	Now func() time.Time
}

type cacheEntry struct {
	CPE     string          `json:"cpe"`
	Fetched time.Time       `json:"fetched"`
	Vulns   []Vulnerability `json:"vulns"`
}

func (c Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Get returns a cached answer if one is present and still fresh.
func (c Cache) Get(cpe string) ([]Vulnerability, bool) {
	if c.Dir == "" {
		return nil, false
	}
	raw, err := os.ReadFile(c.path(cpe))
	if err != nil {
		return nil, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, false
	}
	if c.now().Sub(entry.Fetched) > cacheTTL {
		return nil, false
	}
	return entry.Vulns, true
}

// Put stores an answer. A cache write failing is not worth failing a scan over.
func (c Cache) Put(cpe string, vulns []Vulnerability) error {
	if c.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(cacheEntry{CPE: cpe, Fetched: c.now(), Vulns: vulns})
	if err != nil {
		return err
	}
	path := c.path(cpe)
	tmp, err := os.CreateTemp(c.Dir, ".cve-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// path turns a CPE into a filename. CPEs contain colons and asterisks, so they
// are flattened rather than trusted as a path — a lookup key must never be able
// to escape the cache directory.
func (c Cache) path(cpe string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, cpe)
	if len(safe) > 120 {
		safe = safe[:120]
	}
	return filepath.Join(c.Dir, safe+".json")
}

// Prune deletes entries older than the TTL, so an abandoned cache does not grow
// without bound.
func (c Cache) Prune() error {
	if c.Dir == "" {
		return nil
	}
	entries, err := os.ReadDir(c.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pruning cve cache: %w", err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if c.now().Sub(info.ModTime()) > cacheTTL {
			_ = os.Remove(filepath.Join(c.Dir, e.Name()))
		}
	}
	return nil
}
