package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

func TestCPEMappingAndVersionNormalisation(t *testing.T) {
	tests := []struct {
		product, version string
		wantCPE          string
	}{
		// NVD does not know what "9.6p1" is; it knows 9.6.
		{"OpenSSH", "9.6p1", "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"},
		{"nginx", "1.25.3", "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"},
		{"Apache", "2.4.58 (Ubuntu)", "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"},
		{"Samba", "4.19.5-Debian", "cpe:2.3:a:samba:samba:4.19.5:*:*:*:*:*:*:*"},
	}
	for _, tc := range tests {
		p, ok := Lookup(tc.product)
		if !ok {
			t.Fatalf("Lookup(%q) failed", tc.product)
		}
		if got := CPE(p, tc.version); got != tc.wantCPE {
			t.Errorf("CPE(%s %s) = %q, want %q", tc.product, tc.version, got, tc.wantCPE)
		}
	}
}

func TestUnknownProductIsNotGuessedAt(t *testing.T) {
	// A wrong mapping does not produce no answer — it produces confident wrong
	// answers about somebody else's software.
	if _, ok := Lookup("SomeVendorAppliance"); ok {
		t.Error("an unmapped product must not resolve")
	}
	if got := CPE(Product{"x", "y"}, "not-a-version"); got != "" {
		t.Errorf("CPE with an unparseable version = %q, want empty", got)
	}
}

func nvdStub(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const sampleNVD = `{"vulnerabilities":[
 {"cve":{"id":"CVE-2024-0001","published":"2024-01-01T00:00:00","descriptions":[{"lang":"en","value":"A serious flaw."}],
   "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},"cisaVulnerabilityName":"Known Exploited"}},
 {"cve":{"id":"CVE-2024-0002","published":"2024-02-01T00:00:00","descriptions":[{"lang":"en","value":"A milder flaw."}],
   "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.3,"baseSeverity":"MEDIUM"}}]}}}
]}`

func testClient(t *testing.T, body string) *Client {
	return &Client{BaseURL: nvdStub(t, body).URL, HTTP: http.DefaultClient, Now: func() time.Time { return time.Now() }}
}

func TestQueryParsesAndRanksWorstFirst(t *testing.T) {
	vulns, err := testClient(t, sampleNVD).Query(context.Background(), "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("got %d vulns, want 2", len(vulns))
	}
	if vulns[0].ID != "CVE-2024-0001" {
		t.Errorf("worst should sort first, got %s", vulns[0].ID)
	}
	if vulns[0].Score != 9.8 || vulns[0].Severity != "CRITICAL" {
		t.Errorf("metrics = %.1f/%s", vulns[0].Score, vulns[0].Severity)
	}
	if !vulns[0].KnownRansom {
		t.Error("a CISA-named CVE should be flagged")
	}
	if vulns[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" {
		t.Errorf("url = %q", vulns[0].URL)
	}
}

func TestQuerySurfacesRateLimitingAsAdvice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	_, err := (&Client{BaseURL: srv.URL, HTTP: http.DefaultClient}).Query(context.Background(), "cpe:x")
	if err == nil || !strings.Contains(err.Error(), "NVD_API_KEY") {
		t.Errorf("a 403 should point at the fix, got %v", err)
	}
}

func TestQuerySendsTheKeyAndTheCPE(t *testing.T) {
	var gotKey, gotCPE string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("apiKey")
		gotCPE = r.URL.Query().Get("cpeName")
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{BaseURL: srv.URL, HTTP: http.DefaultClient, APIKey: "secret"}
	if _, err := c.Query(context.Background(), "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if gotKey != "secret" {
		t.Errorf("api key header = %q", gotKey)
	}
	if gotCPE != "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*" {
		t.Errorf("cpeName = %q", gotCPE)
	}
}

func TestCacheRoundTripAndExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	c := Cache{Dir: dir, Now: func() time.Time { return now }}

	vulns := []Vulnerability{{ID: "CVE-2024-0001", Score: 9.8}}
	if err := c.Put("cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*", vulns); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := c.Get("cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*")
	if !ok || len(got) != 1 || got[0].ID != "CVE-2024-0001" {
		t.Fatalf("cache miss or wrong content: %v %v", ok, got)
	}

	stale := Cache{Dir: dir, Now: func() time.Time { return now.Add(8 * 24 * time.Hour) }}
	if _, ok := stale.Get("cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"); ok {
		t.Error("an entry older than the TTL should not be served")
	}
}

func TestCacheKeyCannotEscapeItsDirectory(t *testing.T) {
	// A CPE is data from a scan; it must never be trusted as a path.
	dir := t.TempDir()
	c := Cache{Dir: dir}
	if err := c.Put("../../../etc/evil:2.3", []Vulnerability{{ID: "X"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want exactly one file inside the cache dir, got %d", len(entries))
	}
	// The property that matters is that the key cannot introduce a path
	// separator; leading dots in a flat filename are harmless.
	if strings.ContainsAny(entries[0].Name(), `/\`) {
		t.Errorf("cache filename %q carries a path separator", entries[0].Name())
	}
	resolved, err := filepath.Abs(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resolved, dir) {
		t.Errorf("cache wrote to %q, outside %q", resolved, dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "..", "etc", "evil:2.3.json")); err == nil {
		t.Error("the cache wrote outside its directory")
	}
}

func TestPlanQueriesOnlyFullyIdentifiedServices(t *testing.T) {
	hosts := []model.Host{{IP: "192.168.1.10", Services: []model.Service{
		{Port: 22, State: model.StateOpen, Product: "OpenSSH", Version: "9.6p1"},  // queried
		{Port: 80, State: model.StateOpen, Product: "nginx"},                      // no version
		{Port: 443, State: model.StateOpen, Version: "1.2.3"},                     // no product
		{Port: 25, State: model.StateOpen, Product: "MysteryBox", Version: "1.0"}, // unmapped
		{Port: 21, State: model.StateClosed, Product: "vsftpd", Version: "3.0.5"}, // not open
	}}}

	got := plan(hosts)
	if len(got) != 1 {
		t.Fatalf("planned %d queries, want only the fully identified open service: %+v", len(got), got)
	}
	if got[0].Product != "OpenSSH" {
		t.Errorf("planned %q", got[0].Product)
	}
}

func TestPlanGroupsIdenticalServicesIntoOneQuery(t *testing.T) {
	// Ten identical boxes should cost one lookup: fewer queries, and less
	// disclosed about the network.
	var hosts []model.Host
	for _, ip := range []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"} {
		hosts = append(hosts, model.Host{IP: ip, Services: []model.Service{
			{Port: 80, State: model.StateOpen, Product: "nginx", Version: "1.25.3"},
		}})
	}
	got := plan(hosts)
	if len(got) != 1 {
		t.Fatalf("planned %d queries, want 1", len(got))
	}
	if len(got[0].Targets) != 3 {
		t.Errorf("query covers %d targets, want all three hosts", len(got[0].Targets))
	}
}

func TestEnrichUsesTheCacheAndAnnouncesItself(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(sampleNVD))
	}))
	t.Cleanup(srv.Close)

	var notices []string
	e := &Enricher{
		Client: &Client{BaseURL: srv.URL, HTTP: http.DefaultClient},
		Cache:  Cache{Dir: t.TempDir()},
		Notice: func(msg string) { notices = append(notices, msg) },
	}
	hosts := []model.Host{{IP: "192.168.1.10", Services: []model.Service{
		{Port: 22, State: model.StateOpen, Product: "OpenSSH", Version: "9.6p1"},
	}}}

	results, errs := e.Enrich(context.Background(), hosts)
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(results) != 1 || len(results[0].Vulns) != 2 {
		t.Fatalf("results = %+v", results)
	}
	// The disclosure has to be stated, not logged quietly.
	if len(notices) != 1 || !strings.Contains(notices[0], "nvd.nist.gov") {
		t.Errorf("notices = %v, want one naming where the data goes", notices)
	}

	// A second run of an unchanged network should disclose nothing new.
	if _, errs := e.Enrich(context.Background(), hosts); len(errs) != 0 {
		t.Fatalf("second run errs = %v", errs)
	}
	if calls != 1 {
		t.Errorf("made %d requests, want 1 — the cache exists so a re-audit repeats no disclosure", calls)
	}
}

func TestEnrichSurvivesNVDBeingUnreachable(t *testing.T) {
	// A scan that found real exposure must not be thrown away because a third
	// party was down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	e := &Enricher{Client: &Client{BaseURL: srv.URL, HTTP: http.DefaultClient}, Cache: Cache{Dir: t.TempDir()}}
	results, errs := e.Enrich(context.Background(), []model.Host{{IP: "192.168.1.10", Services: []model.Service{
		{Port: 22, State: model.StateOpen, Product: "OpenSSH", Version: "9.6p1"},
	}}})
	if len(results) != 0 {
		t.Errorf("results = %+v, want none", results)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want the failure reported rather than swallowed", errs)
	}
}

func TestFindingsAreHonestAboutWhatAVersionMatchProves(t *testing.T) {
	results := []Result{{
		Host: "192.168.1.10", Port: 22, Product: "OpenSSH", Version: "9.6p1",
		CPE:   "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
		Vulns: []Vulnerability{{ID: "CVE-2024-0001", Score: 9.8, Severity: "CRITICAL", KnownRansom: true, URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}},
	}}
	f := Findings(results)
	if len(f) != 1 {
		t.Fatalf("findings = %d", len(f))
	}
	// A CVSS 9.8 does not become a critical finding: a version match is a lead,
	// and the host may already carry a distro backport.
	if f[0].Severity != model.SevHigh {
		t.Errorf("severity = %q, want high — a version match is not a confirmed vulnerability", f[0].Severity)
	}
	for _, want := range []string{"backport", "lead to verify"} {
		if !strings.Contains(f[0].Detail, want) {
			t.Errorf("detail should say what a version match does not prove: %q", f[0].Detail)
		}
	}
	if !strings.Contains(f[0].Detail, "ransomware") {
		t.Error("a CISA-listed CVE should say so")
	}
	if !strings.Contains(f[0].Evidence, "nvd.nist.gov") {
		t.Error("evidence should link the CVE")
	}
}

func TestSeverityScales(t *testing.T) {
	tests := []struct {
		score float64
		want  model.Severity
	}{{9.8, model.SevHigh}, {7.0, model.SevHigh}, {5.0, model.SevMedium}, {2.1, model.SevLow}}
	for _, tc := range tests {
		if got := severityFor(Vulnerability{Score: tc.score}); got != tc.want {
			t.Errorf("severityFor(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestNoNetworkAccessWithoutIdentifiedServices(t *testing.T) {
	// The flag is opt-in; so is every individual request. Nothing to look up
	// means nothing is sent.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(srv.Close)

	e := &Enricher{Client: &Client{BaseURL: srv.URL, HTTP: http.DefaultClient}, Cache: Cache{Dir: t.TempDir()}}
	e.Enrich(context.Background(), []model.Host{{IP: "192.168.1.10", Services: []model.Service{
		{Port: 445, State: model.StateOpen}, // open, but never identified
	}}})
	if calls != 0 {
		t.Errorf("made %d requests for an unidentified service", calls)
	}
}

func TestNVDResponseWithNoMetricsIsStillUsable(t *testing.T) {
	body := `{"vulnerabilities":[{"cve":{"id":"CVE-2024-9999","descriptions":[{"lang":"en","value":"No score yet."}],"metrics":{}}}]}`
	vulns, err := testClient(t, body).Query(context.Background(), "cpe:x")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-2024-9999" {
		t.Fatalf("vulns = %+v", vulns)
	}
	if vulns[0].Severity != "" || vulns[0].Score != 0 {
		t.Errorf("an unscored CVE should carry no invented score: %+v", vulns[0])
	}
}

func TestCacheEntryIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	c := Cache{Dir: dir}
	if err := c.Put("cpe:x", []Vulnerability{{ID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Errorf("cache file is not valid JSON: %v", err)
	}
}

// TestParsesRealNVDResponse runs the parser over a response captured from the
// live API (OpenSSH 8.0, 2026-08-21). A hand-written stub only proves the
// parser agrees with my idea of the schema; this proves it agrees with NIST's —
// including the details a stub would have missed, like old CVEs carrying only
// CVSS v2 metrics and the CISA field being absent rather than empty.
func TestParsesRealNVDResponse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nvd-openssh-8.0.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)

	cpe := "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*"
	vulns, err := (&Client{BaseURL: srv.URL, HTTP: http.DefaultClient}).Query(context.Background(), cpe)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(vulns) == 0 {
		t.Fatal("parsed no vulnerabilities from a response that contains several")
	}

	var scored, described int
	for _, v := range vulns {
		if !strings.HasPrefix(v.ID, "CVE-") {
			t.Errorf("id = %q, want a CVE identifier", v.ID)
		}
		if v.URL != "https://nvd.nist.gov/vuln/detail/"+v.ID {
			t.Errorf("url = %q", v.URL)
		}
		if v.MatchedCPE != cpe {
			t.Errorf("matched cpe = %q, want the query", v.MatchedCPE)
		}
		if v.Score > 0 {
			scored++
			if v.Severity == "" {
				t.Errorf("%s has a score but no severity — the v2 fallback did not fire", v.ID)
			}
		}
		if v.Summary != "" {
			described++
		}
	}
	if scored == 0 {
		t.Error("no CVE came out with a score; the metrics shape has changed")
	}
	if described == 0 {
		t.Error("no CVE came out with a description")
	}
	// Worst first, so the top of a long list is the part worth reading.
	for i := 1; i < len(vulns); i++ {
		if vulns[i-1].Score < vulns[i].Score {
			t.Fatalf("results are not ranked worst first: %.1f before %.1f", vulns[i-1].Score, vulns[i].Score)
		}
	}
}
