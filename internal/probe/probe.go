// Package probe is the active host-discovery layer of the audit path. It finds
// which hosts in an authorized scope are up, using a portable TCP-ping that
// needs no elevated privileges: a host that either accepts a connection or
// actively refuses one (a RST) is alive, even when every probed port is closed.
//
// Every address probed is filtered through scope.Contains first. probe never
// touches an address the scope has not cleared — that check is not a courtesy,
// it is the package's contract.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

// DefaultPorts are a spread of common services. We only need one of them to
// answer or refuse to prove a host is up, so breadth beats depth here.
var DefaultPorts = []int{80, 443, 22, 445, 3389, 8080}

// DefaultMaxHosts caps how many addresses a single discovery may enumerate, so
// a fat CIDR (a stray /8) fails loudly instead of sweeping sixteen million
// hosts. Raise it deliberately via Options when a large sweep is intended.
const DefaultMaxHosts = 65536

// Options tunes a discovery run. The zero value is usable; Discover fills in
// sane defaults for any field left empty.
type Options struct {
	Ports       []int         // TCP-ping ports; defaults to DefaultPorts
	Timeout     time.Duration // per-connection timeout; default 800ms
	Concurrency int           // parallel probes; default 128
	MaxHosts    int           // enumeration cap; default DefaultMaxHosts
}

func (o Options) withDefaults() Options {
	if len(o.Ports) == 0 {
		o.Ports = DefaultPorts
	}
	if o.Timeout == 0 {
		o.Timeout = 800 * time.Millisecond
	}
	if o.Concurrency == 0 {
		o.Concurrency = 128
	}
	if o.MaxHosts == 0 {
		o.MaxHosts = DefaultMaxHosts
	}
	return o
}

// Stats summarizes a discovery run — enough for the "speed is first-class"
// one-liner the CLI prints.
type Stats struct {
	Candidates int
	Up         int
	Elapsed    time.Duration
}

// Discover enumerates every host in the scope, TCP-pings each, and returns the
// ones that are up. It refuses an empty scope (nothing authorized) and refuses
// to enumerate more than Options.MaxHosts addresses.
func Discover(ctx context.Context, sc *scope.Set, opts Options) ([]model.Host, Stats, error) {
	return DiscoverIn(ctx, sc, sc, opts)
}

// DiscoverIn is Discover with the candidate set separated from the authority.
// Candidates are enumerated from cand (e.g. a named target), but every probe is
// authorized against auth (the --scope file). A candidate outside auth is never
// touched — so naming a target can only ever narrow the authorized scope, never
// widen it.
func DiscoverIn(ctx context.Context, auth, cand *scope.Set, opts Options) ([]model.Host, Stats, error) {
	if auth.Empty() {
		return nil, Stats{}, errors.New("empty scope: nothing is authorized to probe")
	}
	if cand.Empty() {
		return nil, Stats{}, errors.New("no candidate targets to probe")
	}
	opts = opts.withDefaults()

	candidates, err := enumerate(cand, opts.MaxHosts)
	if err != nil {
		return nil, Stats{}, err
	}

	start := time.Now()
	p := &pinger{ports: opts.Ports, timeout: opts.Timeout, scope: auth}

	jobs := make(chan net.IP)
	results := make(chan model.Host)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if h, up := p.ping(ctx, ip); up {
					select {
					case results <- h:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() { wg.Wait(); close(results) }()

	var up []model.Host
	for h := range results {
		up = append(up, h)
	}
	return up, Stats{Candidates: len(candidates), Up: len(up), Elapsed: time.Since(start)}, ctx.Err()
}

// pinger holds the shared, immutable probe config.
type pinger struct {
	ports   []int
	timeout time.Duration
	scope   *scope.Set
}

// ping TCP-pings one address. A connection that succeeds OR is refused proves
// the host is up; a timeout or unreachable error is treated as down (TCP-ping
// cannot distinguish "down" from "every port silently filtered").
func (p *pinger) ping(ctx context.Context, ip net.IP) (model.Host, bool) {
	// Belt-and-suspenders: never probe an address the scope hasn't cleared,
	// even though enumerate only produced in-scope candidates.
	if !p.scope.Contains(ip) {
		return model.Host{}, false
	}
	host := model.Host{IP: ip.String(), DiscoveredBy: "tcp-ping", ScannedAt: time.Now()}
	for _, port := range p.ports {
		if isUp(ctx, ip, port, p.timeout) {
			host.Up = true
			return host, true
		}
	}
	return model.Host{}, false
}

// isUp reports whether a single TCP probe indicates a live host.
func isUp(ctx context.Context, ip net.IP, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	if err == nil {
		conn.Close()
		return true // open port — definitively up
	}
	// A refused connection is a RST from a live host with that port closed.
	return errors.Is(err, syscall.ECONNREFUSED)
}

// enumerate expands the scope's networks into concrete host addresses, skipping
// the network and broadcast addresses of IPv4 blocks wider than /31. It errors
// out if the total would exceed max, rather than sweep an unreasonable range.
func enumerate(sc *scope.Set, max int) ([]net.IP, error) {
	var out []net.IP
	for _, n := range sc.Nets() {
		ones, bits := n.Mask.Size()
		isV4 := n.IP.To4() != nil
		skipEnds := isV4 && bits-ones > 1 // blocks wider than /31 have net+bcast
		for ip := cloneIP(n.IP.Mask(n.Mask)); n.Contains(ip); ip = nextIP(ip) {
			if skipEnds {
				if isNetworkAddr(ip, n) || isBroadcast(ip, n) {
					continue
				}
			}
			out = append(out, cloneIP(ip))
			if len(out) > max {
				return nil, fmt.Errorf("scope enumerates more than %d hosts; narrow it or raise --max-hosts", max)
			}
		}
	}
	return out, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

// nextIP returns ip+1, big-endian, without allocating a new backing array shape.
func nextIP(ip net.IP) net.IP {
	c := cloneIP(ip)
	for i := len(c) - 1; i >= 0; i-- {
		c[i]++
		if c[i] != 0 {
			break
		}
	}
	return c
}

func isNetworkAddr(ip net.IP, n *net.IPNet) bool {
	return ip.Equal(n.IP.Mask(n.Mask))
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	v4 := ip.To4()
	base := n.IP.Mask(n.Mask).To4()
	if v4 == nil || base == nil {
		return false
	}
	bc := make(net.IP, 4)
	for i := range bc {
		bc[i] = base[i] | ^n.Mask[i]
	}
	return ip.Equal(bc)
}
