package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/audit"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/topo"
)

// cmdDiff compares two saved audit runs. It is the auditor's version of what
// the passive watcher does with devices: the last run is the baseline, and what
// matters is what changed since. It scans nothing — both sides come off disk.
func (a *app) cmdDiff(rest []string) error {
	cfg, err := parseDiffFlags(rest)
	if err != nil {
		return codedError{code: 2, err: err}
	}

	before, after, err := a.runPair(cfg.from, cfg.to)
	if err != nil {
		return codedError{code: 2, err: err}
	}

	delta := audit.Diff(before, after)
	audit.WriteDiffText(a.out, a.style, delta)

	if cfg.showMap || cfg.outPath != "" {
		graphDelta := topo.DiffGraphs(before.Graph, after.Graph)
		if graphDelta.Graph.Empty() {
			fmt.Fprintln(a.out, a.style.Dim("\nno map in these runs to compare"))
		} else {
			if cfg.showMap {
				fmt.Fprintf(a.out, "\n%s\n", a.style.Bold("the map, with what moved"))
				topo.WriteASCII(a.out, a.style, graphDelta.Graph)
			}
			if cfg.outPath != "" {
				view := topo.ViewFrom(graphDelta.Graph, after.Hosts, after.Findings)
				view.Title = "Network map — what changed"
				view.Subtitle = fmt.Sprintf("%s → %s · %d added, %d gone, %d worse",
					before.StartedAt.Format(time.RFC1123), after.StartedAt.Format(time.RFC1123),
					len(graphDelta.Added), len(graphDelta.Removed), len(graphDelta.Worse))
				if err := writeAtomic(cfg.outPath, func(f *os.File) error { return topo.WriteHTML(f, view) }); err != nil {
					return codedError{code: 2, err: err}
				}
				fmt.Fprintf(a.out, "\n%s %s\n", a.style.Dim("map written to"), a.style.Cyan(cfg.outPath))
			}
		}
	}

	if !delta.Empty() && delta.Worst().Rank() >= cfg.failOn.Rank() && len(delta.NewFindings) > 0 {
		fmt.Fprintf(a.out, "\n%s\n", a.style.Yellow(fmt.Sprintf(
			"exit 1 — worst new finding is %s, at or above --fail-on %s", delta.Worst(), cfg.failOn)))
		return exitCode(1)
	}
	return nil
}

// runPair resolves which two runs to compare. With no flags it is the previous
// run against the latest — the "what changed overnight" case.
func (a *app) runPair(from, to string) (audit.Report, audit.Report, error) {
	if from != "" && to != "" {
		before, _, err := a.loadRun(from)
		if err != nil {
			return audit.Report{}, audit.Report{}, err
		}
		after, _, err := a.loadRun(to)
		if err != nil {
			return audit.Report{}, audit.Report{}, err
		}
		return before, after, nil
	}

	runs, err := a.store.ListRuns()
	if err != nil {
		return audit.Report{}, audit.Report{}, err
	}
	if len(runs) < 2 {
		return audit.Report{}, audit.Report{}, fmt.Errorf(
			"need two saved runs to compare, found %d in %s — run `stik-net audit --scope <file>` again",
			len(runs), a.store.RunsDir())
	}

	// runs[0] is newest. A single --from pins the older side.
	olderRef := runs[1].Path
	if from != "" {
		olderRef = from
	}
	newerRef := runs[0].Path
	if to != "" {
		newerRef = to
	}

	before, _, err := a.loadRun(olderRef)
	if err != nil {
		return audit.Report{}, audit.Report{}, err
	}
	after, _, err := a.loadRun(newerRef)
	if err != nil {
		return audit.Report{}, audit.Report{}, err
	}

	// Whichever way round they were named, report oldest → newest.
	if !before.StartedAt.IsZero() && !after.StartedAt.IsZero() && after.StartedAt.Before(before.StartedAt) {
		before, after = after, before
	}
	return before, after, nil
}

// diffAgainstPrevious is what `audit --diff` runs after a scan: compare the
// report just produced with the newest one already on disk.
func (a *app) diffAgainstPrevious(report audit.Report) {
	runs, err := a.store.ListRuns()
	if err != nil || len(runs) < 2 {
		fmt.Fprintln(a.out, a.style.Dim("\nno earlier run to compare against — this one becomes the baseline"))
		return
	}
	// runs[0] is the report just saved; runs[1] is the previous one.
	previous, _, err := a.loadRun(runs[1].Path)
	if err != nil {
		fmt.Fprintln(a.err, "stik-net: "+err.Error())
		return
	}
	audit.WriteDiffText(a.out, a.style, audit.Diff(previous, report))
}

type diffConfig struct {
	from    string
	to      string
	outPath string
	showMap bool
	failOn  model.Severity
}

func parseDiffFlags(args []string) (diffConfig, error) {
	cfg := diffConfig{failOn: model.SevHigh}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--from" || strings.HasPrefix(a, "--from="):
			v, err := valueOf(a, "--from", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.from = v
		case a == "--to" || strings.HasPrefix(a, "--to="):
			v, err := valueOf(a, "--to", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.to = v
		case a == "--map":
			cfg.showMap = true
		case a == "--out" || strings.HasPrefix(a, "--out="):
			v, err := valueOf(a, "--out", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.outPath = v
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
		default:
			return cfg, fmt.Errorf("diff: unknown argument %q", a)
		}
	}
	return cfg, nil
}
