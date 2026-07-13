//go:build ignore

// Command gen builds the embedded OUI table from the IEEE MA-L registry.
//
// Regenerate with:
//
//	go run ./internal/identify/ouidata/gen.go          # fetches from IEEE
//	go run ./internal/identify/ouidata/gen.go -in oui.csv
//
// It writes oui.min.gz next to this file: gzip'd "HEXOUI\tShortVendor" lines.
// Vendor names are shortened once, here, so the runtime lookup is a plain map.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

const source = "https://standards-oui.ieee.org/oui/oui.csv"

func main() {
	in := flag.String("in", "", "local oui.csv (default: fetch from IEEE)")
	out := flag.String("out", "internal/identify/ouidata/oui.min.gz", "output path")
	flag.Parse()

	var r io.ReadCloser
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			log.Fatal(err)
		}
		r = f
	} else {
		resp, err := http.Get(source)
		if err != nil {
			log.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("fetch %s: %s", source, resp.Status)
		}
		r = resp.Body
	}
	defer r.Close()

	rows, err := csv.NewReader(r).ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	seen := map[string]string{}
	for _, row := range rows {
		if len(row) < 3 || row[0] != "MA-L" {
			continue // skip header and non-MA-L rows
		}
		oui := strings.ToUpper(strings.TrimSpace(row[1]))
		if len(oui) != 6 {
			continue
		}
		if name := shorten(row[2]); name != "" {
			seen[oui] = name
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	bw := bufio.NewWriter(gz)
	for _, k := range keys {
		fmt.Fprintf(bw, "%s\t%s\n", k, seen[k])
	}
	bw.Flush()
	gz.Close()
	fmt.Printf("wrote %d vendors to %s\n", len(keys), *out)
}

var (
	parens = regexp.MustCompile(`\s*\([^)]*\)`)
	spaces = regexp.MustCompile(`\s+`)
	// Legal-entity suffixes to peel off the end of a company name.
	legal = map[string]bool{
		"inc": true, "inc.": true, "incorporated": true,
		"corp": true, "corp.": true, "corporation": true,
		"co": true, "co.": true, "company": true,
		"ltd": true, "ltd.": true, "limited": true,
		"llc": true, "l.l.c.": true, "llp": true,
		"gmbh": true, "ag": true, "kg": true, "co.,ltd": true, "co.,ltd.": true,
		"sa": true, "s.a.": true, "sas": true, "bv": true, "b.v.": true,
		"nv": true, "n.v.": true, "pty": true, "plc": true, "oy": true,
		"ab": true, "as": true, "srl": true, "s.r.l.": true, "spa": true,
		"s.p.a.": true, "pte": true, "pvt": true, "ltda": true,
	}
)

func shorten(raw string) string {
	name := parens.ReplaceAllString(raw, "")
	name = strings.ReplaceAll(name, ",", " ")
	name = spaces.ReplaceAllString(name, " ")
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	fields := strings.Fields(name)
	for len(fields) > 1 {
		last := strings.ToLower(fields[len(fields)-1])
		if legal[last] || last == "&" || last == "and" {
			fields = fields[:len(fields)-1]
			continue
		}
		break
	}
	out := strings.Join(fields, " ")
	if len(out) > 40 {
		out = strings.TrimSpace(out[:40])
	}
	return out
}
