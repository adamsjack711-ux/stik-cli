package fingerprint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/scope"
)

func scopeOf(t *testing.T, text string) *scope.Set {
	t.Helper()
	s, err := scope.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("scope parse: %v", err)
	}
	return s
}

// bannerListener serves the given greeting to every connection and returns its
// loopback port — the shape of an SSH/SMTP/FTP daemon that talks first.
func bannerListener(t *testing.T, greeting string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(greeting))
			conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// selfSigned builds a self-signed leaf for a TLS test listener.
func selfSigned(t *testing.T, cn string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-48 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"stik.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsListener(t *testing.T, cert tls.Certificate, maxVersion uint16) int {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersion}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_, _ = conn.Write([]byte("* OK Dovecot ready.\r\n"))
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestFingerprintPlainReadsBanner(t *testing.T) {
	port := bannerListener(t, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")
	svc := model.Service{Port: port, Proto: "tcp", State: model.StateOpen}

	got := fingerprintPlain(context.Background(),
		net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), "127.0.0.1", svc,
		time.Now().Add(2*time.Second))

	if got.Product != "OpenSSH" || got.Version != "9.6p1" {
		t.Errorf("product/version = %q/%q, want OpenSSH/9.6p1", got.Product, got.Version)
	}
	if got.Banner != "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3" {
		t.Errorf("banner = %q, want the sanitized greeting", got.Banner)
	}
}

func TestFingerprintSilentServiceStaysOpen(t *testing.T) {
	// A service that says nothing on connect must survive the pass unchanged —
	// still known-open, just unidentified.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	svc := model.Service{Port: port, Proto: "tcp", State: model.StateOpen, Name: "unknown"}

	got := fingerprintPlain(context.Background(),
		net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), "127.0.0.1", svc,
		time.Now().Add(300*time.Millisecond))

	if got.State != model.StateOpen || got.Banner != "" || got.Product != "" {
		t.Errorf("silent service = %+v, want unchanged open service", got)
	}
}

func TestHTTPExchangeReadsServerAndTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		fmt.Fprint(w, "<html><head><title>Router Admin</title></head><body>hi</body></html>")
	}))
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	server, title := httpExchange(conn, "127.0.0.1")
	if server != "nginx/1.25.3" {
		t.Errorf("server = %q, want nginx/1.25.3", server)
	}
	if title != "Router Admin" {
		t.Errorf("title = %q, want Router Admin", title)
	}

	svc := model.Service{Port: 80, State: model.StateOpen}
	applyHTTP(&svc, server, title)
	if svc.Product != "nginx" || svc.Version != "1.25.3" || svc.Banner != "Router Admin" {
		t.Errorf("applyHTTP = %+v, want nginx/1.25.3 with the title as banner", svc)
	}
}

func TestFingerprintTLSReadsCertificate(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	port := tlsListener(t, selfSigned(t, "nas.stik.local", expiry), tls.VersionTLS12)
	svc := model.Service{Port: 993, Proto: "tcp", State: model.StateOpen} // TLS, not HTTPS

	got := fingerprintTLS(context.Background(),
		net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), svc,
		time.Now().Add(2*time.Second))

	if got.TLS == nil {
		t.Fatal("TLS info = nil, want the handshake details")
	}
	if got.TLS.Version != "TLS 1.2" {
		t.Errorf("tls version = %q, want TLS 1.2", got.TLS.Version)
	}
	if got.TLS.Subject != "nas.stik.local" || !got.TLS.SelfSigned {
		t.Errorf("subject/self-signed = %q/%v, want nas.stik.local/true", got.TLS.Subject, got.TLS.SelfSigned)
	}
	if got.TLS.Expired {
		t.Error("expired = true for a cert valid another day")
	}
	if len(got.TLS.DNSNames) != 1 || got.TLS.DNSNames[0] != "stik.local" {
		t.Errorf("dns names = %v, want [stik.local]", got.TLS.DNSNames)
	}
	if got.Product != "Dovecot" {
		t.Errorf("product = %q, want Dovecot from the greeting behind TLS", got.Product)
	}
}

func TestFingerprintTLSFlagsExpiredCert(t *testing.T) {
	port := tlsListener(t, selfSigned(t, "old.stik.local", time.Now().Add(-1*time.Hour)), tls.VersionTLS12)
	svc := model.Service{Port: 993, Proto: "tcp", State: model.StateOpen}

	got := fingerprintTLS(context.Background(),
		net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), svc,
		time.Now().Add(2*time.Second))

	if got.TLS == nil || !got.TLS.Expired {
		t.Errorf("TLS = %+v, want Expired true", got.TLS)
	}
}

func TestEnrichSkipsOutOfScopeAndNonOpen(t *testing.T) {
	port := bannerListener(t, "SSH-2.0-OpenSSH_9.6p1\r\n")
	sc := scopeOf(t, "127.0.0.1/32")

	hosts := []model.Host{
		{IP: "127.0.0.1", Up: true, Services: []model.Service{
			{Port: port, Proto: "tcp", State: model.StateOpen},
			{Port: 9, Proto: "tcp", State: model.StateClosed},
		}},
		{IP: "10.0.0.5", Up: true, Services: []model.Service{
			{Port: port, Proto: "tcp", State: model.StateOpen},
		}},
	}

	out := Enrich(context.Background(), sc, hosts, Options{Timeout: time.Second})

	if got := out[0].Services[0]; got.Product != "OpenSSH" {
		t.Errorf("in-scope open service product = %q, want OpenSSH", got.Product)
	}
	if got := out[0].Services[1]; got.Banner != "" || got.Product != "" {
		t.Errorf("closed service was probed: %+v", got)
	}
	if got := out[1].Services[0]; got.Banner != "" || got.Product != "" {
		t.Errorf("out-of-scope host was probed: %+v", got)
	}
	// The caller's slice must be untouched — Enrich returns a copy.
	if hosts[0].Services[0].Product != "" {
		t.Errorf("input mutated: %+v", hosts[0].Services[0])
	}
}
