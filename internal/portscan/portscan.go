// Package portscan is the active port-enumeration layer. Its default engine is
// a TCP connect scan: portable, unprivileged, and honest about state — an
// accepted connection is open, a refusal (RST) is closed, and silence to the
// timeout is filtered.
//
// Like every active package, it probes only what the scope has cleared. Each
// host is re-checked against scope.Contains before a single port is touched.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

// Scanner probes one host's ports. The interface exists so the M6 SYN engine
// can drop in behind the same audit pipeline.
type Scanner interface {
	Scan(ctx context.Context, host string, ports []int) ([]model.Service, error)
}

// Options tunes a scan run; the zero value is usable.
type Options struct {
	Ports       []int         // ports to probe; defaults to DefaultTopPorts
	Timeout     time.Duration // per-connection timeout; default 700ms
	Concurrency int           // parallel probes across all host:port pairs; default 256

	// Engine, when set, scans a whole host at a time instead of fanning out
	// host:port pairs. The SYN engine needs that shape — it holds one capture
	// handle and one source port per host — while the connect engine is faster
	// with the flat fan-out below, so both paths exist deliberately.
	Engine Scanner
	// HostConcurrency bounds how many hosts an Engine scans at once; default 8.
	HostConcurrency int

	// UDPPorts, when set, adds a UDP pass over the same hosts. It is a separate
	// list because a useful UDP sweep is a dozen ports, not a thousand: UDP has
	// no handshake, so every silent port costs a full timeout.
	UDPPorts []int
}

func (o Options) withDefaults() Options {
	if len(o.Ports) == 0 {
		o.Ports = DefaultTopPorts
	}
	if o.Timeout == 0 {
		o.Timeout = 700 * time.Millisecond
	}
	if o.Concurrency == 0 {
		o.Concurrency = 256
	}
	if o.HostConcurrency == 0 {
		o.HostConcurrency = 8
	}
	return o
}

// Stats summarizes a scan run for the CLI's one-line footer.
type Stats struct {
	Hosts   int
	Ports   int
	Open    int
	Elapsed time.Duration
}

// ConnectScanner is the unprivileged TCP connect engine.
type ConnectScanner struct {
	Timeout time.Duration
}

// Scan probes each port on one host and returns a Service per port. Closed and
// filtered ports are included so callers can tell "refused" from "silent"; most
// callers keep only the open ones (see OpenOnly).
func (s ConnectScanner) Scan(ctx context.Context, host string, ports []int) ([]model.Service, error) {
	to := s.Timeout
	if to == 0 {
		to = 700 * time.Millisecond
	}
	out := make([]model.Service, 0, len(ports))
	for _, port := range ports {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		out = append(out, probePort(ctx, host, port, to))
	}
	return out, nil
}

// ScanHosts runs the connect engine across many hosts concurrently, filling
// each Host.Services with only its open ports. Every host is gated through the
// scope first; an out-of-scope host is skipped, never probed.
func ScanHosts(ctx context.Context, sc *scope.Set, hosts []model.Host, opts Options) ([]model.Host, Stats) {
	opts = opts.withDefaults()
	start := time.Now()

	if opts.Engine != nil {
		result, stats := scanWithEngine(ctx, sc, hosts, opts, start)
		return withUDP(ctx, sc, result, opts, stats, start)
	}

	type job struct {
		hi   int
		port int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	open := make([][]model.Service, len(hosts)) // per-host open services

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				svc := probePort(ctx, hosts[j.hi].IP, j.port, opts.Timeout)
				if svc.State == model.StateOpen {
					mu.Lock()
					open[j.hi] = append(open[j.hi], svc)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for hi := range hosts {
			ip := net.ParseIP(hosts[hi].IP)
			if !sc.Contains(ip) { // gate: skip anything out of scope
				continue
			}
			for _, port := range opts.Ports {
				select {
				case jobs <- job{hi: hi, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()

	result := make([]model.Host, len(hosts))
	copy(result, hosts)
	totalOpen := 0
	for hi := range result {
		svcs := open[hi]
		sort.Slice(svcs, func(a, b int) bool { return svcs[a].Port < svcs[b].Port })
		result[hi].Services = svcs
		totalOpen += len(svcs)
	}

	return withUDP(ctx, sc, result, opts, Stats{
		Hosts:   len(hosts),
		Ports:   len(opts.Ports),
		Open:    totalOpen,
		Elapsed: time.Since(start),
	}, start)
}

// withUDP runs the optional UDP pass and folds its results into each host. Ports
// that came back open|filtered are kept: on UDP that is a real answer, and
// dropping it would hide every service that has nothing to say to a probe.
func withUDP(ctx context.Context, sc *scope.Set, hosts []model.Host, opts Options, stats Stats, start time.Time) ([]model.Host, Stats) {
	if len(opts.UDPPorts) == 0 {
		return hosts, stats
	}
	scanner := &UDPScanner{Timeout: opts.Timeout}
	sem := make(chan struct{}, opts.HostConcurrency)
	extra := make([][]model.Service, len(hosts))
	var wg sync.WaitGroup

	for hi := range hosts {
		if !sc.Contains(net.ParseIP(hosts[hi].IP)) { // the same gate as TCP
			continue
		}
		wg.Add(1)
		go func(hi int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			svcs, _ := scanner.Scan(ctx, hosts[hi].IP, opts.UDPPorts)
			for _, svc := range svcs {
				if svc.State == model.StateOpen || svc.State == model.StateOpenFiltered {
					extra[hi] = append(extra[hi], svc)
				}
			}
		}(hi)
	}
	wg.Wait()

	for hi := range hosts {
		if len(extra[hi]) == 0 {
			continue
		}
		hosts[hi].Services = append(hosts[hi].Services, extra[hi]...)
		for _, svc := range extra[hi] {
			if svc.State == model.StateOpen {
				stats.Open++
			}
		}
	}
	stats.Ports += len(opts.UDPPorts)
	stats.Elapsed = time.Since(start)
	return hosts, stats
}

// probePort performs one connect probe and classifies the outcome.
func probePort(ctx context.Context, host string, port int, timeout time.Duration) model.Service {
	svc := model.Service{Port: port, Proto: "tcp", Name: ServiceName(port)}
	d := net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err == nil {
		conn.Close()
		svc.State = model.StateOpen
		return svc
	}
	// A refusal means the host is reachable but the port is closed; anything
	// else (timeout, unreachable) we can't distinguish from silence → filtered.
	if isRefused(err) {
		svc.State = model.StateClosed
	} else {
		svc.State = model.StateFiltered
	}
	return svc
}

// scanWithEngine drives a per-host Scanner (the SYN engine) over the in-scope
// hosts, bounded by HostConcurrency. The scope is checked here exactly as it is
// on the connect path: an engine never sees an address the scope rejected.
func scanWithEngine(ctx context.Context, sc *scope.Set, hosts []model.Host, opts Options, start time.Time) ([]model.Host, Stats) {
	open := make([][]model.Service, len(hosts))
	sem := make(chan struct{}, opts.HostConcurrency)
	var wg sync.WaitGroup

	for hi := range hosts {
		if !sc.Contains(net.ParseIP(hosts[hi].IP)) { // gate
			continue
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(hi int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			svcs, err := opts.Engine.Scan(ctx, hosts[hi].IP, opts.Ports)
			if err != nil && len(svcs) == 0 {
				return
			}
			for _, svc := range svcs {
				if svc.State == model.StateOpen {
					open[hi] = append(open[hi], svc)
				}
			}
		}(hi)
	}
	wg.Wait()

	result := make([]model.Host, len(hosts))
	copy(result, hosts)
	totalOpen := 0
	for hi := range result {
		svcs := open[hi]
		sort.Slice(svcs, func(a, b int) bool { return svcs[a].Port < svcs[b].Port })
		result[hi].Services = svcs
		totalOpen += len(svcs)
	}
	return result, Stats{
		Hosts:   len(hosts),
		Ports:   len(opts.Ports),
		Open:    totalOpen,
		Elapsed: time.Since(start),
	}
}
