package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/adamsjack711-ux/stik-cli/internal/unifi"
)

// writeJSON emits the map for another tool to consume. Credentials are never
// part of the map, so there is nothing here to redact.
func writeJSON(m unifi.Map) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		fmt.Fprintln(os.Stderr, "stik-unifi: "+err.Error())
		return 1
	}
	return 0
}
