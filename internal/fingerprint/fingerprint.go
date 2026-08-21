// Package fingerprint reads what a service actually is off the wire: a banner
// (SSH/SMTP/FTP greetings), an HTTP Server header and page title, and — for TLS
// services — the certificate a host presents. It verifies nothing and trusts
// nothing; it reports what the service says about itself.
//
// It only ever talks to open ports on hosts the scope has cleared. Enrich
// re-checks scope.Contains for every host before touching it.
package fingerprint

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

// Options tunes the fingerprint pass; the zero value is usable.
type Options struct {
	Timeout     time.Duration // per-service dial+read budget; default 2s
	Concurrency int           // parallel service probes; default 64
}

func (o Options) withDefaults() Options {
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Concurrency == 0 {
		o.Concurrency = 64
	}
	return o
}

// Port classes. TLS ports get a handshake first; http/https ports also get an
// HTTP exchange; everything else is a passive banner read.
var (
	tlsPorts   = set(443, 8443, 993, 995, 465, 990, 989, 992, 563, 636, 5986)
	httpsPorts = set(443, 8443, 5986) // TLS + speaks HTTP
	httpPorts  = set(80, 81, 631, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9090, 10000)
)

// Enrich fingerprints every open service on every in-scope host, mutating the
// returned copy's Services in place with Product/Version/Banner/TLS.
func Enrich(ctx context.Context, sc *scope.Set, hosts []model.Host, opts Options) []model.Host {
	opts = opts.withDefaults()
	out := make([]model.Host, len(hosts))
	copy(out, hosts)

	type job struct{ hi, si int }
	jobs := make(chan job)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				h := &out[j.hi]
				h.Services[j.si] = fingerprintOne(ctx, h.IP, h.Services[j.si], opts.Timeout)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for hi := range out {
			if !sc.Contains(net.ParseIP(out[hi].IP)) { // gate
				continue
			}
			// out[hi].Services must be copied so we don't mutate the caller's slice.
			out[hi].Services = append([]model.Service(nil), out[hi].Services...)
			for si := range out[hi].Services {
				if out[hi].Services[si].State != model.StateOpen {
					continue
				}
				select {
				case jobs <- job{hi: hi, si: si}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	wg.Wait()
	return out
}

// fingerprintOne enriches a single open service. Any probe failure leaves the
// service as-is (still known-open) rather than dropping it.
func fingerprintOne(ctx context.Context, host string, svc model.Service, timeout time.Duration) model.Service {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", svc.Port))
	deadline := time.Now().Add(timeout)

	if tlsPorts[svc.Port] {
		return fingerprintTLS(ctx, addr, svc, deadline)
	}
	return fingerprintPlain(ctx, addr, host, svc, deadline)
}

func fingerprintTLS(ctx context.Context, addr string, svc model.Service, deadline time.Time) model.Service {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 — inspecting, not trusting
	cctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return svc
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	tc := conn.(*tls.Conn)
	svc.TLS = tlsInfoFrom(tc.ConnectionState())

	if httpsPorts[svc.Port] {
		if server, title := httpExchange(conn, hostOnly(addr)); server != "" || title != "" {
			applyHTTP(&svc, server, title)
		}
		return svc
	}
	// Non-HTTP TLS service (imaps, pop3s, smtps): read its greeting.
	if b := readBanner(conn); b != "" {
		applyBanner(&svc, b)
	}
	return svc
}

func fingerprintPlain(ctx context.Context, addr, host string, svc model.Service, deadline time.Time) model.Service {
	d := net.Dialer{}
	cctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return svc
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	if httpPorts[svc.Port] {
		if server, title := httpExchange(conn, host); server != "" || title != "" {
			applyHTTP(&svc, server, title)
			return svc
		}
	}
	// Fall back to a passive banner read for anything that greets on connect.
	if b := readBanner(conn); b != "" {
		applyBanner(&svc, b)
	}
	return svc
}

// httpExchange writes a minimal HTTP/1.0 GET and returns (Server header, title).
func httpExchange(conn net.Conn, host string) (server, title string) {
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: stik-net\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", ""
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	server = resp.Header.Get("Server")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	title = parseHTMLTitle(string(body))
	return server, title
}

// readBanner reads whatever a service volunteers on connect, up to 4KB.
func readBanner(conn net.Conn) string {
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return sanitizeBanner(string(buf[:n]), 200)
}

func applyBanner(svc *model.Service, banner string) {
	svc.Banner = banner
	if pv := parseBanner(banner); pv.Product != "" {
		svc.Product, svc.Version = pv.Product, pv.Version
	}
}

func applyHTTP(svc *model.Service, server, title string) {
	if title != "" && svc.Banner == "" {
		svc.Banner = title
	}
	if pv := parseServerHeader(server); pv.Product != "" {
		svc.Product, svc.Version = pv.Product, pv.Version
	}
}

func tlsInfoFrom(cs tls.ConnectionState) *model.TLSInfo {
	info := &model.TLSInfo{Version: tlsVersionName(cs.Version)}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.Subject = leaf.Subject.CommonName
		info.Issuer = leaf.Issuer.CommonName
		info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		info.Expired = time.Now().After(leaf.NotAfter)
		info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
		info.DNSNames = leaf.DNSNames
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func set(ports ...int) map[int]bool {
	m := make(map[int]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}
