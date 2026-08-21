package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/probe"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

// cmdDiscover is `stik-net discover --scope <file>`: the first active command.
// Unlike the passive watcher, it sends packets — so it refuses to run without
// an explicit on-disk scope of authorized targets, and probes nothing outside
// it.
func (a *app) cmdDiscover(rest []string) error {
	opts, scopePath, err := parseDiscoverFlags(rest)
	if err != nil {
		return err
	}
	if scopePath == "" {
		return errors.New("discover needs --scope <file>: a list of authorized CIDRs/IPs.\n" +
			"Active scanning only runs against targets you've written down as in-bounds.")
	}

	sc, err := scope.Load(scopePath)
	if err != nil {
		return err
	}

	// The registry (if any) lets us name hosts instead of showing bare IPs.
	var reg deviceLookup
	if loaded, _, lerr := a.load(); lerr == nil {
		reg = loaded
	}

	fmt.Fprintf(a.out, "%s %d authorized range(s) from %s (scope %s)\n",
		a.style.Green("stik-net discover"), len(sc.Entries()),
		a.style.Cyan(sc.Source()), a.style.Dim(sc.Fingerprint()))

	ctx, cancel := signalContext()
	defer cancel()

	hosts, stats, err := probe.Discover(ctx, sc, opts)
	if err != nil && !errors.Is(err, ctx.Err()) {
		return err
	}

	printHosts(a, reg, hosts)
	fmt.Fprintf(a.out, "\n%s %d up of %d probed in %s\n",
		a.style.Bold("done —"), stats.Up, stats.Candidates, stats.Elapsed.Round(time.Millisecond))
	return nil
}

// deviceLookup is the slice of the registry discover needs: names for IPs.
type deviceLookup interface {
	Devices() []*model.Device
}

func printHosts(a *app, reg deviceLookup, hosts []model.Host) {
	if len(hosts) == 0 {
		fmt.Fprintln(a.out, a.style.Dim("no live hosts found in scope"))
		return
	}
	byIP := map[string]*model.Device{}
	if reg != nil {
		for _, d := range reg.Devices() {
			if d.IP != "" {
				byIP[d.IP] = d
			}
		}
	}
	fmt.Fprintln(a.out)
	for _, h := range hosts {
		name := a.style.Dim("unknown host")
		if d, ok := byIP[h.IP]; ok {
			name = d.Display()
			if d.Vendor != "" && d.Name == "" {
				name = d.Display() + a.style.Dim(" ("+d.Vendor+")")
			}
		}
		fmt.Fprintf(a.out, "  %s  %s\n", a.style.Bold(padIP(h.IP)), name)
	}
}

// padIP right-pads an address so the name column lines up for both v4 and v6.
func padIP(ip string) string {
	const w = 15 // widest common IPv4
	if len(ip) < w {
		return ip + strings.Repeat(" ", w-len(ip))
	}
	return ip
}

func parseDiscoverFlags(args []string) (probe.Options, string, error) {
	var opts probe.Options
	var scopePath string
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		switch {
		case a == "--scope":
			v, err := next()
			if err != nil {
				return opts, "", err
			}
			scopePath = v
		case strings.HasPrefix(a, "--scope="):
			scopePath = strings.TrimPrefix(a, "--scope=")
		case a == "--ports" || strings.HasPrefix(a, "--ports="):
			v, err := valueOf(a, "--ports", &i, args)
			if err != nil {
				return opts, "", err
			}
			ports, err := parsePorts(v)
			if err != nil {
				return opts, "", err
			}
			opts.Ports = ports
		case a == "--timeout" || strings.HasPrefix(a, "--timeout="):
			v, err := valueOf(a, "--timeout", &i, args)
			if err != nil {
				return opts, "", err
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return opts, "", fmt.Errorf("--timeout: %w", err)
			}
			opts.Timeout = d
		case a == "--concurrency" || strings.HasPrefix(a, "--concurrency="):
			v, err := valueOf(a, "--concurrency", &i, args)
			if err != nil {
				return opts, "", err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return opts, "", fmt.Errorf("--concurrency: want a positive integer, got %q", v)
			}
			opts.Concurrency = n
		case a == "--max-hosts" || strings.HasPrefix(a, "--max-hosts="):
			v, err := valueOf(a, "--max-hosts", &i, args)
			if err != nil {
				return opts, "", err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return opts, "", fmt.Errorf("--max-hosts: want a positive integer, got %q", v)
			}
			opts.MaxHosts = n
		default:
			return opts, "", fmt.Errorf("discover: unknown flag %q", a)
		}
	}
	return opts, scopePath, nil
}

// valueOf reads a flag value in either "--flag value" or "--flag=value" form.
func valueOf(arg, name string, i *int, args []string) (string, error) {
	if strings.HasPrefix(arg, name+"=") {
		return strings.TrimPrefix(arg, name+"="), nil
	}
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s needs a value", name)
	}
	*i++
	return args[*i], nil
}

func parsePorts(csv string) ([]int, error) {
	var ports []int
	for _, tok := range strings.Split(csv, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--ports: invalid port %q", tok)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("--ports: no valid ports given")
	}
	return ports, nil
}
