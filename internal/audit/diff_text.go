package audit

import (
	"fmt"
	"io"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// WriteDiffText renders what changed between two runs. Silence is the good
// outcome and gets said explicitly — "nothing changed" is a result, not an
// empty page.
func WriteDiffText(w io.Writer, s ui.Style, d Delta) {
	fmt.Fprintf(w, "\n%s %s → %s\n",
		s.Bold("change since last audit"),
		s.Dim(stamp(d.Before.StartedAt)), s.Dim(stamp(d.After.StartedAt)))

	if d.Empty() {
		fmt.Fprintf(w, "\n%s\n", s.Green("nothing changed — same hosts, same open ports, same findings"))
		return
	}
	fmt.Fprintln(w)

	for _, ip := range d.NewHosts {
		fmt.Fprintf(w, "  %s %s %s\n", s.Yellow("+ host"), s.Bold(ip), nameSuffix(s, d.After, ip))
	}
	for _, ip := range d.GoneHosts {
		fmt.Fprintf(w, "  %s %s %s\n", s.Dim("- host"), s.Bold(ip), nameSuffix(s, d.Before, ip))
	}
	for _, c := range d.Opened {
		fmt.Fprintf(w, "  %s %s %s %s\n", s.Yellow("+ port"),
			s.Bold(fmt.Sprintf("%s:%d", c.Host, c.Service.Port)), label(c.Service), whose(s, c.Name))
	}
	for _, c := range d.Closed {
		fmt.Fprintf(w, "  %s %s %s %s\n", s.Dim("- port"),
			s.Bold(fmt.Sprintf("%s:%d", c.Host, c.Service.Port)), label(c.Service), whose(s, c.Name))
	}

	if len(d.NewFindings) > 0 {
		fmt.Fprintf(w, "\n%s\n", s.Bold("new findings"))
		for _, f := range d.NewFindings {
			fmt.Fprintf(w, "  %s %s  %s\n",
				colorFor(s, f.Severity)(padSev(f.Severity)), f.Title, s.Dim(where(f)))
		}
	}
	if len(d.ResolvedFindings) > 0 {
		fmt.Fprintf(w, "\n%s\n", s.Bold("no longer present"))
		for _, f := range d.ResolvedFindings {
			fmt.Fprintf(w, "  %s %s  %s\n", s.Green(padSev(f.Severity)), f.Title, s.Dim(where(f)))
		}
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02 15:04:05")
}

func nameSuffix(s ui.Style, r Report, ip string) string {
	if n, ok := r.Named(ip); ok {
		return n
	}
	return s.Dim("unknown host")
}

func whose(s ui.Style, name string) string {
	if name == "" {
		return ""
	}
	return s.Dim("(" + name + ")")
}

func label(svc model.Service) string {
	return serviceLabel(svc)
}

func where(f model.Finding) string {
	if f.Port > 0 {
		return fmt.Sprintf("%s:%d · %s", f.Host, f.Port, f.ID)
	}
	return fmt.Sprintf("%s · %s", f.Host, f.ID)
}

func padSev(sev model.Severity) string {
	s := string(sev)
	for len(s) < 8 {
		s += " "
	}
	return s
}
