package audit

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// WriteText renders a report for a terminal: the scorecard, then findings
// worst-first with their evidence, then the inventory of what was reachable.
func WriteText(w io.Writer, s ui.Style, r Report) {
	fmt.Fprintf(w, "\n%s  %s  %s\n",
		s.Bold("audit"), s.Cyan(r.Scope.Source), s.Dim(r.Scope.Fingerprint))
	fmt.Fprintf(w, "%s\n\n", s.Dim(fmt.Sprintf("%d host(s) up, %d open service(s), %s",
		len(r.Hosts), r.OpenServices(), r.Elapsed.Round(time.Millisecond))))

	writeScorecard(w, s, r)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "\n%s\n", s.Green("nothing to report — no rule fired on anything reachable"))
	} else {
		fmt.Fprintln(w)
		for _, f := range r.Findings {
			writeFinding(w, s, r, f)
		}
	}
	writeInventory(w, s, r)
}

func writeScorecard(w io.Writer, s ui.Style, r Report) {
	counts := r.Counts()
	var cells []string
	for _, sev := range Severities {
		if counts[sev] == 0 {
			continue
		}
		cells = append(cells, colorFor(s, sev)(fmt.Sprintf("%d %s", counts[sev], sev)))
	}
	if len(cells) == 0 {
		fmt.Fprintln(w, s.Green("clean — 0 findings"))
		return
	}
	fmt.Fprintln(w, strings.Join(cells, s.Dim("  ·  ")))
}

func writeFinding(w io.Writer, s ui.Style, r Report, f model.Finding) {
	where := r.Name(f.Host)
	if where != f.Host {
		where = fmt.Sprintf("%s (%s)", where, f.Host)
	}
	if f.Port > 0 {
		where = fmt.Sprintf("%s · %d/tcp", where, f.Port)
	}
	fmt.Fprintf(w, "%s %s\n", colorFor(s, f.Severity)(strings.ToUpper(string(f.Severity))), s.Bold(f.Title))
	fmt.Fprintf(w, "  %s  %s\n", where, s.Dim(f.ID))
	fmt.Fprintf(w, "  %s\n", f.Detail)
	if f.Evidence != "" {
		fmt.Fprintf(w, "  %s %s\n", s.Dim("evidence:"), f.Evidence)
	}
	if f.Fix != "" {
		fmt.Fprintf(w, "  %s %s\n", s.Dim("fix:"), f.Fix)
	}
	fmt.Fprintln(w)
}

func writeInventory(w io.Writer, s ui.Style, r Report) {
	if len(r.Hosts) == 0 {
		return
	}
	fmt.Fprintf(w, "%s\n", s.Bold("what's reachable"))
	for _, h := range r.Hosts {
		name := s.Dim("unknown host")
		if n, ok := r.Named(h.IP); ok {
			name = n
		}
		fmt.Fprintf(w, "  %s  %s\n", s.Bold(padIP(h.IP)), name)
		for _, svc := range h.Services {
			if svc.State != model.StateOpen && svc.State != model.StateOpenFiltered {
				continue
			}
			proto := svc.Proto
			if proto == "" {
				proto = "tcp"
			}
			state := ""
			if svc.State == model.StateOpenFiltered {
				state = s.Dim(" open|filtered")
			}
			fmt.Fprintf(w, "      %s/%s  %s%s\n", padPort(svc.Port), proto, serviceLabel(svc), state)
		}
	}
}

// serviceLabel is the compact "what is it" for the inventory line.
func serviceLabel(s model.Service) string {
	parts := []string{}
	if s.Name != "" {
		parts = append(parts, s.Name)
	}
	if s.Product != "" {
		p := s.Product
		if s.Version != "" {
			p += " " + s.Version
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 && s.Banner != "" {
		parts = append(parts, s.Banner)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "  ")
}

func colorFor(s ui.Style, sev model.Severity) func(string) string {
	switch sev {
	case model.SevCritical, model.SevHigh:
		return s.Red
	case model.SevMedium:
		return s.Yellow
	case model.SevLow:
		return s.Cyan
	default:
		return s.Dim
	}
}

func padIP(ip string) string {
	const w = 15
	if len(ip) < w {
		return ip + strings.Repeat(" ", w-len(ip))
	}
	return ip
}

func padPort(p int) string {
	s := fmt.Sprintf("%d", p)
	if len(s) < 5 {
		return strings.Repeat(" ", 5-len(s)) + s
	}
	return s
}
