package ui

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/identify"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Status prints the one-line (usually boring) verdict for `stik`. Boring is the
// feature: if nothing new has appeared, the user learns that in one glance.
func Status(w io.Writer, s Style, devices []*model.Device, now time.Time) {
	known, unknown := partition(devices)

	if len(devices) == 0 {
		fmt.Fprintln(w, s.Dim("No devices recorded yet.")+" Run "+s.Bold("stik watch")+" to take a look at your network.")
		return
	}

	if len(unknown) == 0 {
		fmt.Fprintf(w, "%s Everything looks normal. %s known %s.\n",
			s.Green("✓"), s.Bold(fmt.Sprint(len(known))), plural(len(known), "device", "devices"))
		return
	}

	// Lead with the most recently-arrived unknown device.
	sort.SliceStable(unknown, func(i, j int) bool {
		return unknown[i].FirstSeen.After(unknown[j].FirstSeen)
	})
	newest := unknown[0]

	headline := fmt.Sprintf("%s new %s joined %s.",
		numberWord(len(unknown)), plural(len(unknown), "device", "devices"), HumanSince(newest.FirstSeen, now))
	fmt.Fprintf(w, "%s %s\n", s.Yellow("⚠"), s.Bold(headline))
	fmt.Fprintf(w, "  %s, first seen %s.\n", newest.Display(), ClockTime(newest.FirstSeen))
	if newest.Label != "" && newest.Name == "" {
		fmt.Fprintf(w, "  %s\n", s.Dim(reasonFor(newest)))
	}
	fmt.Fprintf(w, "  Run %s to see it, or %s to label it.\n", s.Bold("stik devices"), s.Bold("stik name"))
}

// DeviceList prints every device in human terms. Names come first; the MAC and
// other raw details only appear under --verbose.
func DeviceList(w io.Writer, s Style, devices []*model.Device, verbose bool, now time.Time) {
	if len(devices) == 0 {
		fmt.Fprintln(w, s.Dim("No devices recorded yet.")+" Run "+s.Bold("stik watch")+" first.")
		return
	}
	known, unknown := partition(devices)

	if len(unknown) > 0 {
		fmt.Fprintln(w, s.Bold("New — not yet in your baseline"))
		for _, d := range unknown {
			printDevice(w, s, d, verbose, now, s.Yellow("•"))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, s.Bold(fmt.Sprintf("Known (%d)", len(known))))
	for _, d := range known {
		printDevice(w, s, d, verbose, now, s.Green("•"))
	}
}

func printDevice(w io.Writer, s Style, d *model.Device, verbose bool, now time.Time, bullet string) {
	name := d.Display()
	sub := ""
	if d.Name != "" && d.Label != "" {
		sub = s.Dim(" (" + d.Label + ")")
	}
	fmt.Fprintf(w, "  %s %s%s\n", bullet, name, sub)
	fmt.Fprintf(w, "      last seen %s", HumanSince(d.LastSeen, now))
	if d.Hostname != "" {
		fmt.Fprintf(w, " · %s", d.Hostname)
	}
	fmt.Fprintln(w)
	if verbose {
		fmt.Fprintf(w, "      %s\n", s.Dim(verboseLine(d)))
	}
}

func verboseLine(d *model.Device) string {
	parts := []string{"mac " + d.MAC}
	if d.IP != "" {
		parts = append(parts, "ip "+d.IP)
	}
	if d.Private {
		parts = append(parts, "private/randomized address")
	} else if d.Vendor != "" {
		parts = append(parts, "vendor "+d.Vendor)
	}
	if d.DHCPFingerprint != "" {
		parts = append(parts, "dhcp "+d.DHCPFingerprint)
	}
	if d.DHCPVendorClass != "" {
		parts = append(parts, "class "+d.DHCPVendorClass)
	}
	return joinDot(parts)
}

func partition(devices []*model.Device) (known, unknown []*model.Device) {
	for _, d := range devices {
		if d.Known {
			known = append(known, d)
		} else {
			unknown = append(unknown, d)
		}
	}
	return known, unknown
}

// reasonFor recomputes the plain-English justification for a device, so the
// wording always reflects the current facts rather than a stale stored string.
func reasonFor(d *model.Device) string {
	return identify.Identify(identify.Input{
		MAC:             d.MAC,
		Hostname:        d.Hostname,
		DHCPFingerprint: d.DHCPFingerprint,
		DHCPVendorClass: d.DHCPVendorClass,
	}).Reason
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func numberWord(n int) string {
	words := []string{"No", "A", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"}
	if n >= 0 && n < len(words) {
		return words[n]
	}
	return fmt.Sprint(n)
}

func joinDot(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " · "
		}
		out += p
	}
	return out
}
