package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/audit"
	"github.com/adamsjack711-ux/stik-cli/internal/fingerprint"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/portscan"
	"github.com/adamsjack711-ux/stik-cli/internal/probe"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

// cmdAudit is the headline active command: discover → port-scan → fingerprint →
// rules → report. Like the other active commands it refuses to run without an
// explicit scope file, and every stage re-checks that scope before it touches
// an address.
//
// Exit codes follow the CI convention: 0 when nothing reaches the threshold,
// 1 when something does, 2 when the run itself failed.
func (a *app) cmdAudit(rest []string) error {
	err := a.auditRun(rest)
	var code exitCode
	if err != nil && !errors.As(err, &code) {
		// A failed run is exit 2; only findings are exit 1.
		return codedError{code: 2, err: err}
	}
	return err
}

func (a *app) auditRun(rest []string) error {
	cfg, err := parseAuditFlags(rest)
	if err != nil {
		return err
	}
	if cfg.scopePath == "" {
		return errors.New("audit needs --scope <file>: a list of authorized CIDRs/IPs.\n" +
			"Active scanning only runs against targets you've written down as in-bounds.")
	}

	auth, err := scope.Load(cfg.scopePath)
	if err != nil {
		return err
	}

	cand := auth
	if cfg.target != "" {
		cand, err = scope.Parse(strings.NewReader(cfg.target))
		if err != nil {
			return fmt.Errorf("target %q: %w", cfg.target, err)
		}
	}

	var reg deviceLookup
	if loaded, _, lerr := a.load(); lerr == nil {
		reg = loaded
	}

	fmt.Fprintf(a.out, "%s scope %s (%s), %d ports\n",
		a.style.Green("stik-net audit"), a.style.Cyan(auth.Source()),
		a.style.Dim(auth.Fingerprint()), len(cfg.ports))

	ctx, cancel := signalContext()
	defer cancel()
	started := time.Now()

	hosts, _, err := probe.DiscoverIn(ctx, auth, cand, probe.Options{Timeout: cfg.timeout})
	if err != nil && !errors.Is(err, ctx.Err()) {
		return err
	}
	fmt.Fprintf(a.out, "%s %d host(s) up\n", a.style.Dim("discovered"), len(hosts))

	if len(hosts) > 0 {
		var stats portscan.Stats
		hosts, stats = portscan.ScanHosts(ctx, auth, hosts, portscan.Options{
			Ports:       cfg.ports,
			Timeout:     cfg.timeout,
			Concurrency: cfg.concurrency,
		})
		fmt.Fprintf(a.out, "%s %d open port(s)\n", a.style.Dim("scanned"), stats.Open)
		hosts = fingerprint.Enrich(ctx, auth, hosts, fingerprint.Options{Timeout: cfg.timeout})
	}

	report := audit.Report{
		Version:   version,
		Scope:     audit.ScopeInfo{Source: auth.Source(), Fingerprint: auth.Fingerprint(), Entries: auth.Entries()},
		StartedAt: started,
		Elapsed:   time.Since(started),
		Hosts:     hosts,
		Findings:  audit.Evaluate(hosts),
		Names:     deviceNames(reg),
	}

	audit.WriteText(a.out, a.style, report)

	if cfg.outPath != "" {
		if err := writeHTMLReport(cfg.outPath, report); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "\n%s %s\n", a.style.Dim("report written to"), a.style.Cyan(cfg.outPath))
	}

	if report.Worst().Rank() >= cfg.failOn.Rank() && len(report.Findings) > 0 {
		fmt.Fprintf(a.out, "%s\n", a.style.Yellow(fmt.Sprintf(
			"exit 1 — worst finding is %s, at or above --fail-on %s", report.Worst(), cfg.failOn)))
		return exitCode(1)
	}
	return nil
}

// writeHTMLReport writes the deliverable atomically, so a half-written file
// never replaces a good report from an earlier run.
func writeHTMLReport(path string, r audit.Report) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stik-report-*")
	if err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := audit.WriteHTML(tmp, r); err != nil {
		tmp.Close()
		return fmt.Errorf("writing report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

// deviceNames is the IP → friendly-name join that makes an audit report read
// "Jack's NAS · 445/tcp" instead of an IP soup.
func deviceNames(reg deviceLookup) map[string]string {
	if reg == nil {
		return nil
	}
	names := map[string]string{}
	for _, d := range reg.Devices() {
		if d.IP != "" {
			names[d.IP] = d.Display()
		}
	}
	return names
}

type auditConfig struct {
	scopePath   string
	target      string
	outPath     string
	ports       []int
	timeout     time.Duration
	concurrency int
	failOn      model.Severity
}

func parseAuditFlags(args []string) (auditConfig, error) {
	cfg := auditConfig{ports: portscan.DefaultTopPorts, failOn: model.SevHigh}
	var top int
	var full bool
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--scope" || strings.HasPrefix(a, "--scope="):
			v, err := valueOf(a, "--scope", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.scopePath = v
		case a == "--out" || strings.HasPrefix(a, "--out="):
			v, err := valueOf(a, "--out", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.outPath = v
		case a == "--ports" || strings.HasPrefix(a, "--ports="):
			v, err := valueOf(a, "--ports", &i, args)
			if err != nil {
				return cfg, err
			}
			ports, err := parsePorts(v)
			if err != nil {
				return cfg, err
			}
			cfg.ports = ports
		case a == "--top" || strings.HasPrefix(a, "--top="):
			v, err := valueOf(a, "--top", &i, args)
			if err != nil {
				return cfg, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return cfg, fmt.Errorf("--top: want a positive integer, got %q", v)
			}
			top = n
		case a == "--full":
			full = true
		case a == "--timeout" || strings.HasPrefix(a, "--timeout="):
			v, err := valueOf(a, "--timeout", &i, args)
			if err != nil {
				return cfg, err
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return cfg, fmt.Errorf("--timeout: %w", err)
			}
			cfg.timeout = d
		case a == "--concurrency" || strings.HasPrefix(a, "--concurrency="):
			v, err := valueOf(a, "--concurrency", &i, args)
			if err != nil {
				return cfg, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return cfg, fmt.Errorf("--concurrency: want a positive integer, got %q", v)
			}
			cfg.concurrency = n
		case a == "--fail-on" || strings.HasPrefix(a, "--fail-on="):
			v, err := valueOf(a, "--fail-on", &i, args)
			if err != nil {
				return cfg, err
			}
			sev, ok := model.ParseSeverity(strings.ToLower(v))
			if !ok {
				return cfg, fmt.Errorf("--fail-on: want one of info, low, medium, high, critical; got %q", v)
			}
			cfg.failOn = sev
		case strings.HasPrefix(a, "--"):
			return cfg, fmt.Errorf("audit: unknown flag %q", a)
		default:
			if cfg.target != "" {
				return cfg, fmt.Errorf("audit: unexpected extra argument %q", a)
			}
			cfg.target = a
		}
	}

	switch {
	case full:
		cfg.ports = allPorts()
	case top > 0:
		if top > len(portscan.DefaultTopPorts) {
			top = len(portscan.DefaultTopPorts)
		}
		cfg.ports = portscan.DefaultTopPorts[:top]
	}
	return cfg, nil
}
