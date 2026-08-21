package audit

import (
	"sort"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// ScopeInfo records what the run was authorized to touch, so a report can say
// for itself which ranges it covered and which file said so.
type ScopeInfo struct {
	Source      string   `json:"source"`      // path of the scope file
	Fingerprint string   `json:"fingerprint"` // hash of its contents
	Entries     []string `json:"entries"`     // the authorized ranges
}

// Report is one audit run: what it was allowed to scan, what it found alive,
// and what the rules made of that.
type Report struct {
	Version   string            `json:"version"`
	Scope     ScopeInfo         `json:"scope"`
	StartedAt time.Time         `json:"started_at"`
	Elapsed   time.Duration     `json:"elapsed"`
	Hosts     []model.Host      `json:"hosts"`
	Findings  []model.Finding   `json:"findings"`
	Names     map[string]string `json:"names,omitempty"` // IP → friendly device name
	Graph     model.Graph       `json:"graph,omitempty"` // inferred topology, drawn by internal/topo
}

// Evaluate runs every rule against every open service and returns the findings
// ranked worst-first. Services that are not open are ignored: a rule must never
// fire on a port the scan couldn't reach.
func Evaluate(hosts []model.Host) []model.Finding {
	var findings []model.Finding
	for _, h := range hosts {
		for _, svc := range h.Services {
			if svc.State != model.StateOpen {
				continue
			}
			for _, rule := range Rules {
				evidence, ok := rule.Match(svc)
				if !ok {
					continue
				}
				findings = append(findings, model.Finding{
					ID:       rule.ID,
					Host:     h.IP,
					Port:     svc.Port,
					Severity: rule.Severity,
					Title:    rule.Title,
					Detail:   rule.Detail,
					Evidence: evidence,
					Fix:      rule.Fix,
				})
			}
		}
	}
	Sort(findings)
	return findings
}

// Sort ranks findings worst-first, then by host and port so a re-run of an
// unchanged network produces an identical report.
func Sort(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.ID < b.ID
	})
}

// Counts is the scorecard: how many findings at each severity.
func (r Report) Counts() map[model.Severity]int {
	counts := map[model.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// Worst is the highest severity in the report, or info when it is clean.
func (r Report) Worst() model.Severity {
	worst := model.SevInfo
	for _, f := range r.Findings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// OpenServices counts every open port across every scanned host.
func (r Report) OpenServices() int {
	n := 0
	for _, h := range r.Hosts {
		for _, s := range h.Services {
			if s.State == model.StateOpen {
				n++
			}
		}
	}
	return n
}

// Name is the friendly device name for an IP, falling back to the address so
// callers never have to branch.
func (r Report) Name(ip string) string {
	if n, ok := r.Names[ip]; ok && n != "" {
		return n
	}
	return ip
}

// Named reports the friendly device name for an IP, and whether the passive
// registry knew it at all — callers render an unknown host differently from one
// that merely happens to be named after its address.
func (r Report) Named(ip string) (string, bool) {
	n, ok := r.Names[ip]
	return n, ok && n != "" && n != ip
}

// FindingsFor returns the findings on one host, in report order.
func (r Report) FindingsFor(ip string) []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.Host == ip {
			out = append(out, f)
		}
	}
	return out
}

// Severities is the display order for scorecards: worst first.
var Severities = []model.Severity{
	model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo,
}
