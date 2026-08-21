package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/fingerprint"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/portscan"
	"github.com/adamsjack711-ux/stik-cli/internal/probe"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

// cmdPorts is `stik-net ports [target] --scope <file>`: discover live hosts in
// the authorized scope (or the named target within it), then TCP connect-scan
// each. Like discover, it refuses to run without a scope and touches nothing
// outside it.
func (a *app) cmdPorts(rest []string) error {
	cfg, err := parsePortsFlags(rest)
	if err != nil {
		return err
	}
	if cfg.scopePath == "" {
		return errors.New("ports needs --scope <file>: a list of authorized CIDRs/IPs.\n" +
			"Active scanning only runs against targets you've written down as in-bounds.")
	}

	auth, err := scope.Load(cfg.scopePath)
	if err != nil {
		return err
	}

	// A named target narrows the scan; it must itself be inside the scope.
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

	// Resolve the engine before anything is sent: an unusable --engine must fail
	// before the first packet, and a fallback must be visible from the start.
	engine, engineName, err := a.engineFor(cfg.engine, cfg.timeout)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "%s scope %s (%s), %d ports, %s engine\n",
		a.style.Green("stik-net ports"), a.style.Cyan(auth.Source()),
		a.style.Dim(auth.Fingerprint()), len(cfg.ports), engineName)

	ctx, cancel := signalContext()
	defer cancel()

	hosts, dstats, err := probe.DiscoverIn(ctx, auth, cand, probe.Options{Timeout: cfg.timeout})
	if err != nil && !errors.Is(err, ctx.Err()) {
		return err
	}
	if len(hosts) == 0 {
		fmt.Fprintln(a.out, a.style.Dim("no live hosts found in scope"))
		return nil
	}

	scanned, sstats := portscan.ScanHosts(ctx, auth, hosts, portscan.Options{
		Ports:       cfg.ports,
		Timeout:     cfg.timeout,
		Concurrency: cfg.concurrency,
		Engine:      engine,
		UDPPorts:    cfg.udpPorts,
	})

	var fpElapsed time.Duration
	if cfg.fingerprint && sstats.Open > 0 {
		start := time.Now()
		scanned = fingerprint.Enrich(ctx, auth, scanned, fingerprint.Options{Timeout: cfg.timeout})
		fpElapsed = time.Since(start)
	}

	printPortResults(a, reg, scanned)
	fmt.Fprintf(a.out, "\n%s %d host(s), %d open port(s) across %d probed — discovery %s, %s scan %s",
		a.style.Bold("done —"), sstats.Hosts, sstats.Open, sstats.Ports,
		dstats.Elapsed.Round(time.Millisecond), engineName, sstats.Elapsed.Round(time.Millisecond))
	if fpElapsed > 0 {
		fmt.Fprintf(a.out, ", fingerprint %s", fpElapsed.Round(time.Millisecond))
	}
	fmt.Fprintln(a.out)
	return nil
}

func printPortResults(a *app, reg deviceLookup, hosts []model.Host) {
	byIP := map[string]*model.Device{}
	if reg != nil {
		for _, d := range reg.Devices() {
			if d.IP != "" {
				byIP[d.IP] = d
			}
		}
	}
	for _, h := range hosts {
		name := a.style.Dim("unknown host")
		if d, ok := byIP[h.IP]; ok {
			name = d.Display()
		}
		fmt.Fprintf(a.out, "\n%s  %s\n", a.style.Bold(h.IP), name)
		if len(h.Services) == 0 {
			fmt.Fprintln(a.out, "  "+a.style.Dim("no open ports"))
			continue
		}
		for _, s := range h.Services {
			label := s.Name
			if label == "" {
				label = a.style.Dim("unknown")
			}
			proto := s.Proto
			if proto == "" {
				proto = "tcp"
			}
			state := a.style.Green("open")
			if s.State == model.StateOpenFiltered {
				// UDP silence. Saying "open" here would be a guess presented as a
				// result, so the column says what was actually observed.
				state = a.style.Dim("open|filt")
			}
			fmt.Fprintf(a.out, "  %s/%s  %-9s  %-8s %s\n",
				a.style.Bold(padPort(s.Port)), proto, state, label, serviceDetail(a, s))
		}
	}
}

// serviceDetail is the one-line "what is it" suffix from the fingerprint pass:
// product/version first, then the TLS story, then whatever the service said.
func serviceDetail(a *app, s model.Service) string {
	var parts []string
	if s.Product != "" {
		p := s.Product
		if s.Version != "" {
			p += " " + s.Version
		}
		parts = append(parts, a.style.Cyan(p))
	}
	if s.TLS != nil {
		tlsPart := s.TLS.Version
		switch {
		case s.TLS.Expired:
			tlsPart += ", cert expired"
		case s.TLS.SelfSigned:
			tlsPart += ", self-signed"
		}
		parts = append(parts, a.style.Dim(tlsPart))
	}
	if s.Banner != "" && s.Product == "" {
		parts = append(parts, a.style.Dim(truncate(s.Banner, 60)))
	}
	return strings.Join(parts, "  ")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func padPort(p int) string {
	s := strconv.Itoa(p)
	if len(s) < 5 {
		return strings.Repeat(" ", 5-len(s)) + s
	}
	return s
}

type portsConfig struct {
	scopePath   string
	target      string
	ports       []int
	timeout     time.Duration
	concurrency int
	fingerprint bool
	engine      string
	udpPorts    []int
}

func parsePortsFlags(args []string) (portsConfig, error) {
	cfg := portsConfig{ports: portscan.DefaultTopPorts, fingerprint: true}
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
		case a == "--no-fingerprint":
			cfg.fingerprint = false
		case a == "--udp":
			cfg.udpPorts = portscan.DefaultUDPPorts
		case a == "--udp-ports" || strings.HasPrefix(a, "--udp-ports="):
			v, err := valueOf(a, "--udp-ports", &i, args)
			if err != nil {
				return cfg, err
			}
			ports, err := parsePorts(v)
			if err != nil {
				return cfg, err
			}
			cfg.udpPorts = ports
		case a == "--engine" || strings.HasPrefix(a, "--engine="):
			v, err := valueOf(a, "--engine", &i, args)
			if err != nil {
				return cfg, err
			}
			cfg.engine = v
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
		case strings.HasPrefix(a, "--"):
			return cfg, fmt.Errorf("ports: unknown flag %q", a)
		default:
			if cfg.target != "" {
				return cfg, fmt.Errorf("ports: unexpected extra argument %q", a)
			}
			cfg.target = a
		}
	}

	// Resolve the port set: --full wins, then --top, else --ports/default.
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

func allPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}
