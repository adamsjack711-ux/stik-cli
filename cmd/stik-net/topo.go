package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/audit"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/topo"
)

// cmdTopo draws the network map. With --from it re-renders a saved run and
// touches nothing: redrawing the picture must never mean re-scanning the
// network. With --scope it runs a fresh audit pass first, under the same gate
// as every other active command.
func (a *app) cmdTopo(rest []string) error {
	cfg, err := parseTopoFlags(rest)
	if err != nil {
		return codedError{code: 2, err: err}
	}

	var report audit.Report
	var source string
	switch {
	case cfg.from != "":
		report, source, err = a.loadRun(cfg.from)
		if err != nil {
			return codedError{code: 2, err: err}
		}
		fmt.Fprintf(a.out, "%s %s %s\n", a.style.Green("stik-net topo"),
			a.style.Dim("redrawing"), a.style.Cyan(source))
	case cfg.scopePath != "":
		report, err = a.auditPass(auditConfig{
			scopePath:   cfg.scopePath,
			target:      cfg.target,
			ports:       cfg.ports,
			timeout:     cfg.timeout,
			concurrency: cfg.concurrency,
		})
		if err != nil {
			return codedError{code: 2, err: err}
		}
	default:
		// Default to the last saved run: the quiet path, not the scanning one.
		report, source, err = a.loadRun("last")
		if err != nil {
			return codedError{code: 2, err: fmt.Errorf("%w\n\nOr map a fresh scan with: stik-net topo --scope <file>", err)}
		}
		fmt.Fprintf(a.out, "%s %s %s\n", a.style.Green("stik-net topo"),
			a.style.Dim("redrawing"), a.style.Cyan(source))
	}

	if report.Graph.Empty() {
		fmt.Fprintln(a.out, a.style.Dim("nothing to map — that run reached no hosts"))
		return nil
	}

	if cfg.outPath == "" || cfg.ascii {
		topo.WriteASCII(a.out, a.style, report.Graph)
	}
	if cfg.outPath != "" {
		view := topo.ViewFrom(report.Graph, report.Hosts, report.Findings)
		view.Title = "Network map"
		view.Subtitle = fmt.Sprintf("%s · %d host(s) · scope %s",
			report.StartedAt.Format(time.RFC1123), len(report.Hosts), report.Scope.Source)
		if err := writeAtomic(cfg.outPath, func(f *os.File) error { return topo.WriteHTML(f, view) }); err != nil {
			return codedError{code: 2, err: err}
		}
		fmt.Fprintf(a.out, "\n%s %s\n", a.style.Dim("map written to"), a.style.Cyan(cfg.outPath))
	}
	return nil
}

// loadRun reads a saved audit run from disk.
func (a *app) loadRun(ref string) (audit.Report, string, error) {
	data, path, err := a.store.LoadRun(ref)
	if err != nil {
		return audit.Report{}, "", err
	}
	var report audit.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return audit.Report{}, "", fmt.Errorf("run %s is not readable: %w", path, err)
	}
	return report, path, nil
}

// graphFor infers the topology from a finished scan, handing the inference
// everything the passive registry knows: names, MACs, and who serves DHCP.
func graphFor(report audit.Report, reg deviceLookup, subnets []*net.IPNet) model.Graph {
	in := topo.Input{
		Hosts:    report.Hosts,
		Findings: report.Findings,
		Names:    report.Names,
		Subnets:  subnets,
		LocalIPs: topo.LocalAddresses(),
	}
	if reg != nil {
		in.MACs = map[string]string{}
		in.DHCPServers = map[string]bool{}
		for _, d := range reg.Devices() {
			if d.IP == "" {
				continue
			}
			in.MACs[d.IP] = d.MAC
			if d.DHCPServer {
				in.DHCPServers[d.IP] = true
			}
		}
	}
	return topo.Build(in)
}

type topoConfig struct {
	from        string
	scopePath   string
	target      string
	outPath     string
	ascii       bool
	ports       []int
	timeout     time.Duration
	concurrency int
}

func parseTopoFlags(args []string) (topoConfig, error) {
	cfg := topoConfig{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--from" || strings.HasPrefix(a, "--from="):
			v, err := valueOf(a, "--from", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.from = v
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
		case a == "--ascii":
			cfg.ascii = true
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
		case strings.HasPrefix(a, "--"):
			return cfg, fmt.Errorf("topo: unknown flag %q", a)
		default:
			if cfg.target != "" {
				return cfg, fmt.Errorf("topo: unexpected extra argument %q", a)
			}
			cfg.target = a
		}
	}
	if cfg.from != "" && cfg.scopePath != "" {
		return cfg, errors.New("topo: --from redraws a saved run and --scope runs a new scan; pick one")
	}
	return cfg, nil
}
