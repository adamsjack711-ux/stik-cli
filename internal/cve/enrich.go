package cve

import (
	"context"
	"fmt"
	"sort"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Enricher looks up the services a scan identified. It queries only services
// whose product AND version were actually determined — asking about a product
// we merely guessed at would produce confident answers about software that may
// not be there.
type Enricher struct {
	Client *Client
	Cache  Cache

	// Notice reports what is about to be disclosed and what was skipped. This
	// is the one place stik-net talks to a third party, so it says so.
	Notice func(string)
}

// Result is what a lookup produced for one service.
type Result struct {
	Host    string
	Port    int
	Product string
	Version string
	CPE     string
	Vulns   []Vulnerability
}

// Enrich looks up every identified service across the given hosts and returns
// the results, worst first. Errors are collected rather than fatal: a scan that
// found real exposure should not be thrown away because NVD was unreachable.
func (e *Enricher) Enrich(ctx context.Context, hosts []model.Host) ([]Result, []error) {
	queries := plan(hosts)
	if len(queries) == 0 {
		e.notify("no service was identified precisely enough to look up — CVE matching needs both a product and a version")
		return nil, nil
	}

	e.notify(fmt.Sprintf(
		"looking up %d identified service(s) at nvd.nist.gov. This sends product and version names — not addresses, not host names — to NIST. Answers are cached for a week.",
		len(queries)))

	var results []Result
	var errs []error
	for _, q := range queries {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		vulns, cached := e.Cache.Get(q.CPE)
		if !cached {
			fetched, err := e.Client.Query(ctx, q.CPE)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", q.Product, q.Version, err))
				continue
			}
			vulns = fetched
			if err := e.Cache.Put(q.CPE, vulns); err != nil {
				errs = append(errs, fmt.Errorf("caching %s: %w", q.CPE, err))
			}
		}
		if len(vulns) == 0 {
			continue
		}
		for _, target := range q.Targets {
			results = append(results, Result{
				Host: target.host, Port: target.port,
				Product: q.Product, Version: q.Version, CPE: q.CPE, Vulns: vulns,
			})
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		return topScore(results[i].Vulns) > topScore(results[j].Vulns)
	})
	return results, errs
}

func (e *Enricher) notify(msg string) {
	if e.Notice != nil {
		e.Notice(msg)
	}
}

type target struct {
	host string
	port int
}

type query struct {
	Product string
	Version string
	CPE     string
	Targets []target
}

// plan groups services by product+version, so ten identical nginx boxes cost
// one lookup rather than ten — fewer queries, and less disclosed.
func plan(hosts []model.Host) []query {
	index := map[string]*query{}
	var order []string

	for _, h := range hosts {
		for _, svc := range h.Services {
			if svc.State != model.StateOpen || svc.Product == "" || svc.Version == "" {
				continue
			}
			p, known := Lookup(svc.Product)
			if !known {
				continue
			}
			cpe := CPE(p, svc.Version)
			if cpe == "" {
				continue
			}
			q, seen := index[cpe]
			if !seen {
				q = &query{Product: svc.Product, Version: svc.Version, CPE: cpe}
				index[cpe] = q
				order = append(order, cpe)
			}
			q.Targets = append(q.Targets, target{host: h.IP, port: svc.Port})
		}
	}

	out := make([]query, 0, len(order))
	for _, cpe := range order {
		out = append(out, *index[cpe])
	}
	return out
}

func topScore(vulns []Vulnerability) float64 {
	best := 0.0
	for _, v := range vulns {
		if v.Score > best {
			best = v.Score
		}
	}
	return best
}

// Findings turns lookup results into audit findings. Severity comes from NVD's
// own CVSS rating, capped at high: a CVE matched by version alone is a lead to
// verify, not a confirmed vulnerability on this host, and calling it critical
// would overstate what a port scan can know.
func Findings(results []Result) []model.Finding {
	var out []model.Finding
	for _, r := range results {
		worst := r.Vulns[0]
		sev := severityFor(worst)
		detail := fmt.Sprintf(
			"NVD lists %d known vulnerabilit%s for %s %s. Worst: %s (CVSS %.1f). Matched on version alone — this host may already carry a distro backport, so treat it as a lead to verify rather than a confirmed finding.",
			len(r.Vulns), plural(len(r.Vulns)), r.Product, r.Version, worst.ID, worst.Score)
		if worst.KnownRansom {
			detail += " CISA lists this CVE as used in ransomware campaigns."
		}
		out = append(out, model.Finding{
			ID:       "STIK-CVE",
			Host:     r.Host,
			Port:     r.Port,
			Severity: sev,
			Title:    fmt.Sprintf("%s %s has known CVEs (%s)", r.Product, r.Version, worst.ID),
			Detail:   detail,
			Evidence: fmt.Sprintf("%s · %s", r.CPE, worst.URL),
			Fix:      fmt.Sprintf("Check %s against your installed build, and update %s if it applies.", worst.ID, r.Product),
		})
	}
	return out
}

func severityFor(v Vulnerability) model.Severity {
	switch {
	case v.KnownRansom:
		return model.SevHigh
	case v.Score >= 7.0:
		return model.SevHigh
	case v.Score >= 4.0:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
