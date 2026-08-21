package audit

import (
	"sort"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Diffing two saved runs is the audit equivalent of what the passive watcher
// does with devices: the baseline is what was normal last time, and the useful
// output is what changed since. A re-audit that reprints thirty unchanged
// findings buries the one port that opened yesterday.

// ServiceChange is one port appearing or disappearing on a host.
type ServiceChange struct {
	Host    string        `json:"host"`
	Name    string        `json:"name,omitempty"` // friendly device name, when known
	Service model.Service `json:"service"`
}

// Delta is everything that changed between two runs, oldest first.
type Delta struct {
	Before, After Report `json:"-"`

	NewHosts  []string `json:"new_hosts,omitempty"`
	GoneHosts []string `json:"gone_hosts,omitempty"`

	Opened []ServiceChange `json:"opened,omitempty"`
	Closed []ServiceChange `json:"closed,omitempty"`

	NewFindings      []model.Finding `json:"new_findings,omitempty"`
	ResolvedFindings []model.Finding `json:"resolved_findings,omitempty"`
}

// Empty reports whether nothing changed at all.
func (d Delta) Empty() bool {
	return len(d.NewHosts) == 0 && len(d.GoneHosts) == 0 &&
		len(d.Opened) == 0 && len(d.Closed) == 0 &&
		len(d.NewFindings) == 0 && len(d.ResolvedFindings) == 0
}

// Worst is the highest severity among findings that are new in this run. A
// finding that was already there is not news; a pipeline gating on change
// should fail for what appeared, not for what it already knew about.
func (d Delta) Worst() model.Severity {
	worst := model.SevInfo
	for _, f := range d.NewFindings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// Diff compares two runs. Hosts are keyed by IP, services by host+port, and
// findings by rule+host+port — so the same finding re-observed on the same port
// is continuity, not news.
func Diff(before, after Report) Delta {
	d := Delta{Before: before, After: after}

	beforeHosts := hostIndex(before)
	afterHosts := hostIndex(after)

	for ip := range afterHosts {
		if _, existed := beforeHosts[ip]; !existed {
			d.NewHosts = append(d.NewHosts, ip)
		}
	}
	for ip := range beforeHosts {
		if _, still := afterHosts[ip]; !still {
			d.GoneHosts = append(d.GoneHosts, ip)
		}
	}
	sortIPs(d.NewHosts)
	sortIPs(d.GoneHosts)

	beforePorts := openIndex(before)
	afterPorts := openIndex(after)

	for key, svc := range afterPorts {
		if _, existed := beforePorts[key]; !existed {
			d.Opened = append(d.Opened, ServiceChange{
				Host: key.host, Name: nameFor(after, key.host), Service: svc,
			})
		}
	}
	for key, svc := range beforePorts {
		if _, still := afterPorts[key]; !still {
			// A port on a host that vanished entirely is covered by GoneHosts;
			// reporting it again as a closed port would double-count one event.
			if _, hostStillUp := afterHosts[key.host]; !hostStillUp {
				continue
			}
			d.Closed = append(d.Closed, ServiceChange{
				Host: key.host, Name: nameFor(before, key.host), Service: svc,
			})
		}
	}
	sortChanges(d.Opened)
	sortChanges(d.Closed)

	beforeFindings := findingIndex(before)
	afterFindings := findingIndex(after)

	for key, f := range afterFindings {
		if _, existed := beforeFindings[key]; !existed {
			d.NewFindings = append(d.NewFindings, f)
		}
	}
	for key, f := range beforeFindings {
		if _, still := afterFindings[key]; !still {
			d.ResolvedFindings = append(d.ResolvedFindings, f)
		}
	}
	Sort(d.NewFindings)
	Sort(d.ResolvedFindings)

	return d
}

type portKey struct {
	host string
	port int
}

type findingKey struct {
	id   string
	host string
	port int
}

func hostIndex(r Report) map[string]model.Host {
	out := make(map[string]model.Host, len(r.Hosts))
	for _, h := range r.Hosts {
		out[h.IP] = h
	}
	return out
}

func openIndex(r Report) map[portKey]model.Service {
	out := map[portKey]model.Service{}
	for _, h := range r.Hosts {
		for _, s := range h.Services {
			if s.State != model.StateOpen {
				continue
			}
			out[portKey{host: h.IP, port: s.Port}] = s
		}
	}
	return out
}

func findingIndex(r Report) map[findingKey]model.Finding {
	out := make(map[findingKey]model.Finding, len(r.Findings))
	for _, f := range r.Findings {
		out[findingKey{id: f.ID, host: f.Host, port: f.Port}] = f
	}
	return out
}

func nameFor(r Report, ip string) string {
	if n, ok := r.Named(ip); ok {
		return n
	}
	return ""
}

func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool { return model.LessIP(ips[i], ips[j]) })
}

func sortChanges(changes []ServiceChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Host != changes[j].Host {
			return model.LessIP(changes[i].Host, changes[j].Host)
		}
		return changes[i].Service.Port < changes[j].Service.Port
	})
}
