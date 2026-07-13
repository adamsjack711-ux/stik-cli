// Package ouidata embeds the IEEE MA-L registry and answers "which vendor owns
// this MAC prefix?" entirely offline — stik never fetches anything at runtime,
// so it works on a network it doesn't trust. Regenerate oui.min.gz with gen.go.
package ouidata

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.min.gz
var compressed []byte

var (
	once  sync.Once
	table map[string]string
)

func load() {
	table = make(map[string]string, 40000)
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return
	}
	defer gz.Close()
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		key, name, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			table[key] = name
		}
	}
}

// Lookup returns the vendor for a normalized MAC ("aa:bb:cc:dd:ee:ff"), using
// its first three bytes. The bool is false when the prefix isn't registered.
func Lookup(mac string) (string, bool) {
	once.Do(load)
	key := prefix(mac)
	if key == "" {
		return "", false
	}
	name, ok := table[key]
	return name, ok
}

// Count reports how many OUI prefixes are embedded (used in tests).
func Count() int {
	once.Do(load)
	return len(table)
}

func prefix(mac string) string {
	hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(mac))
	if len(hex) < 6 {
		return ""
	}
	return hex[:6]
}
