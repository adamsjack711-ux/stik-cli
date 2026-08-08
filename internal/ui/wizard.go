package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
)

// WizardResult reports what the naming wizard accomplished.
type WizardResult struct {
	Named    int
	Acked    int // marked known without a name ("not mine")
	Deferred int // skipped, left as unknown
}

// RunWizard walks the user through every device found, one at a time. This is
// the product's first moment: it builds the trusted baseline, makes all future
// output legible, and gets the person to actually look at their own network.
func RunWizard(in io.Reader, out io.Writer, s Style, reg *registry.Registry, devices []*model.Device) WizardResult {
	r := bufio.NewReader(in)
	var res WizardResult

	fmt.Fprintf(out, "\nFound %s %s on your network. Let's figure out what they are.\n\n",
		s.Bold(fmt.Sprint(len(devices))), plural(len(devices), "device", "devices"))

	for i, d := range devices {
		host := d.Hostname
		if host == "" {
			host = s.Dim("no hostname")
		} else {
			host = "\"" + host + "\""
		}
		fmt.Fprintf(out, "  %s  %s — %s\n", s.Bold(fmt.Sprintf("%d/%d", i+1, len(devices))), d.Label, host)
		fmt.Fprintf(out, "       %s\n", s.Dim(reasonFor(d)))

		answer, ok := ask(r, out, s, "       Is this yours?  [Y/n/skip] ")
		if !ok {
			// input closed (non-interactive): stop cleanly, leave the rest for later
			fmt.Fprintln(out)
			return res
		}

		switch normalizeAnswer(answer) {
		case "n":
			reg.Accept(d.MAC, "")
			res.Acked++
			fmt.Fprintf(out, "       %s\n\n", s.Dim("noted — not yours, but part of your normal network."))
		case "skip":
			res.Deferred++
			fmt.Fprintf(out, "       %s\n\n", s.Dim("skipped — I'll keep flagging it until you name it."))
		default: // yes
			name, _ := ask(r, out, s, "       name it: ")
			name = strings.TrimSpace(name)
			if name == "" {
				name = d.Hostname // fall back to the announced hostname
			}
			reg.Accept(d.MAC, name)
			res.Named++
			if name != "" {
				fmt.Fprintf(out, "       %s %s\n\n", s.Green("✓"), s.Dim("saved as \""+name+"\""))
			} else {
				fmt.Fprintf(out, "       %s\n\n", s.Green("✓ saved"))
			}
		}
	}

	fmt.Fprintf(out, "%s Baseline set: %d named, %d acknowledged, %d skipped.\n",
		s.Green("✓"), res.Named, res.Acked, res.Deferred)
	fmt.Fprintf(out, "From now on, %s tells you when something new shows up.\n", s.Bold("stik-net"))
	return res
}

func ask(r *bufio.Reader, out io.Writer, s Style, prompt string) (string, bool) {
	fmt.Fprint(out, prompt)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return strings.TrimSpace(line), true
}

func normalizeAnswer(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	switch {
	case a == "":
		return "yes"
	case strings.HasPrefix(a, "s"):
		return "skip"
	case strings.HasPrefix(a, "n"):
		return "n"
	default:
		return "yes"
	}
}

// DevicesForWizard returns the devices a fresh sweep should present, most
// recently seen first so the active ones come up early.
func DevicesForWizard(reg *registry.Registry) []*model.Device {
	return reg.SortedByLastSeen()
}
