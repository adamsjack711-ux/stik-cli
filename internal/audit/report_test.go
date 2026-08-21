package audit

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/topo"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

func sampleReport() Report {
	hosts := []model.Host{
		hostWith("192.168.1.1", open(80, func(s *model.Service) { s.Name = "http"; s.Banner = "Router Admin Login" })),
		hostWith("192.168.1.20", open(445, func(s *model.Service) { s.Name = "microsoft-ds" })),
	}
	return Report{
		Version:   "test",
		Scope:     ScopeInfo{Source: "auth.txt", Fingerprint: "abc123", Entries: []string{"192.168.1.0/24"}},
		StartedAt: time.Date(2026, 8, 21, 14, 0, 0, 0, time.UTC),
		Elapsed:   1500 * time.Millisecond,
		Hosts:     hosts,
		Findings:  Evaluate(hosts),
		Names:     map[string]string{"192.168.1.20": "Jack's NAS"},
	}
}

func TestWriteTextShowsFindingsAndNames(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, ui.Style{}, sampleReport())
	out := buf.String()

	for _, want := range []string{
		"SMB reachable on the network", // the finding
		"Jack's NAS (192.168.1.20)",    // the registry join
		"445/tcp",
		"STIK-A004",   // rule id
		"evidence:",   // the claim is backed
		"fix:",        // and actionable
		"1 high",      // scorecard
		"1 medium",    // the admin-panel finding
		"192.168.1.1", // inventory
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal report missing %q\n---\n%s", want, out)
		}
	}
}

func TestWriteTextOnCleanReport(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, ui.Style{}, Report{
		Scope: ScopeInfo{Source: "auth.txt", Fingerprint: "abc123"},
		Hosts: []model.Host{hostWith("192.168.1.5", open(22, func(s *model.Service) { s.Name = "ssh" }))},
	})
	out := buf.String()
	if !strings.Contains(out, "clean") && !strings.Contains(out, "nothing to report") {
		t.Errorf("a clean report should say so plainly:\n%s", out)
	}
}

func TestWriteHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Error("report should be a complete HTML document")
	}
	// A deliverable must not fetch anything when it's opened.
	for _, forbidden := range []string{"<script", "src=", "http://", "https://", "@import", "url("} {
		if strings.Contains(out, forbidden) {
			t.Errorf("report is not self-contained: contains %q", forbidden)
		}
	}
	for _, want := range []string{"auth.txt", "abc123", "192.168.1.0/24", "SMB reachable", "Jack&#39;s NAS", "STIK-A004"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestWriteHTMLEscapesHostileBanner(t *testing.T) {
	// A banner is attacker-controlled text. It must reach the page as text.
	hosts := []model.Host{hostWith("10.0.0.9", open(23, func(s *model.Service) {
		s.Banner = `<img src=x onerror="alert(1)">`
	}))}
	r := Report{
		Scope:    ScopeInfo{Source: "auth.txt", Fingerprint: "f", Entries: []string{"10.0.0.0/24"}},
		Hosts:    hosts,
		Findings: Evaluate(hosts),
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<img") {
		t.Error("hostile banner reached the page as markup")
	}
	if strings.Contains(out, `onerror="alert(1)"`) {
		t.Error("hostile banner kept its quoting, so it could break out of a text node")
	}
	if !strings.Contains(out, "&lt;img src=x onerror=") {
		t.Error("hostile banner should still be shown, escaped")
	}
}

func TestWriteHTMLParsesAsBalancedDocument(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	for _, tag := range []string{"html", "head", "body", "main", "style"} {
		opens := len(regexp.MustCompile(`(?i)<`+tag+`[ >]`).FindAllString(out, -1))
		closes := strings.Count(strings.ToLower(out), "</"+tag+">")
		if opens != closes {
			t.Errorf("<%s>: %d opened, %d closed", tag, opens, closes)
		}
	}
	if testing.Verbose() {
		_ = os.WriteFile("/tmp/stik-report-preview.html", buf.Bytes(), 0o644)
	}
}

func TestWriteHTMLEmbedsTheMap(t *testing.T) {
	r := sampleReport()
	r.Graph = topo.Build(topo.Input{Hosts: r.Hosts, Findings: r.Findings, Names: r.Names})

	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<canvas") || !strings.Contains(out, "The map") {
		t.Error("a report with a graph should carry the map")
	}
	// The map ships an inline script; it still must not fetch anything.
	for _, forbidden := range []string{"src=", "http://", "https://", "@import"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("report with a map reaches outside: contains %q", forbidden)
		}
	}
}

func TestWriteHTMLWithoutGraphHasNoMapSection(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if strings.Contains(buf.String(), "<canvas") {
		t.Error("no graph means no map section")
	}
}
