package topo

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

func sampleGraph(t *testing.T) (model.Graph, []model.Host, []model.Finding) {
	t.Helper()
	hosts := []model.Host{
		host("192.168.1.1"),
		host("192.168.1.20", 445),
	}
	hosts[1].Services[0].Name = "microsoft-ds"
	findings := []model.Finding{{
		ID: "STIK-A004", Host: "192.168.1.20", Port: 445,
		Severity: model.SevHigh, Title: "SMB reachable on the network",
	}}
	g := Build(Input{
		Hosts:       hosts,
		Findings:    findings,
		Names:       map[string]string{"192.168.1.20": "Jack's NAS"},
		Subnets:     []*net.IPNet{cidr(t, "192.168.1.0/24")},
		DHCPServers: map[string]bool{"192.168.1.1": true},
	})
	return g, hosts, findings
}

func TestFragmentIsSelfContained(t *testing.T) {
	g, hosts, findings := sampleGraph(t)
	frag, err := Fragment(ViewFrom(g, hosts, findings))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	out := string(frag)

	// An inline script is fine — a fetched one is not. The report has to open
	// on a laptop with no network.
	for _, forbidden := range []string{"src=", "href=", "http://", "https://", "@import", "url("} {
		if strings.Contains(out, forbidden) {
			t.Errorf("map fragment reaches outside: contains %q", forbidden)
		}
	}
	for _, want := range []string{"<canvas", "<script", "192.168.1.20", "Jack&#39;s NAS", "microsoft-ds"} {
		if !strings.Contains(out, want) {
			t.Errorf("map fragment missing %q", want)
		}
	}
}

func TestFragmentKeepsANoScriptFallback(t *testing.T) {
	g, hosts, findings := sampleGraph(t)
	frag, err := Fragment(ViewFrom(g, hosts, findings))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	out := string(frag)
	if !strings.Contains(out, "stik-map-fallback") {
		t.Fatal("a canvas-less reader should still get the node list")
	}
	// The list is real content, not an empty shell hidden by CSS.
	if !strings.Contains(out, "<li><strong>192.168.1.1</strong>") {
		t.Error("fallback list should name the hosts")
	}
}

func TestFragmentEscapesHostileDeviceName(t *testing.T) {
	// A device name comes from mDNS — attacker-controlled. It travels inside a
	// <script> block, so it must not be able to close it.
	hosts := []model.Host{host("10.0.0.5", 80)}
	g := Build(Input{
		Hosts:   hosts,
		Names:   map[string]string{"10.0.0.5": `</script><img src=x onerror="alert(1)">`},
		Subnets: []*net.IPNet{cidr(t, "10.0.0.0/24")},
	})
	frag, err := Fragment(ViewFrom(g, hosts, nil))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	out := string(frag)
	if strings.Contains(out, "</script><img") {
		t.Fatal("hostile device name closed the script tag")
	}
	if !strings.Contains(out, `</script>`) {
		t.Error("the name should survive, escaped, in the JSON payload")
	}
}

func TestWriteHTMLPage(t *testing.T) {
	g, hosts, findings := sampleGraph(t)
	v := ViewFrom(g, hosts, findings)
	v.Title = "Network map"
	v.Subtitle = "2 host(s)"

	var buf bytes.Buffer
	if err := WriteHTML(&buf, v); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Error("want a complete document")
	}
	for _, want := range []string{"<title>Network map</title>", "2 host(s)", "<canvas", "prefers-color-scheme"} {
		if !strings.Contains(out, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(out, "src=") || strings.Contains(out, "http://") {
		t.Error("standalone map must not reference anything external")
	}
}

func TestViewFromCarriesServicesAndFindings(t *testing.T) {
	g, hosts, findings := sampleGraph(t)
	v := ViewFrom(g, hosts, findings)

	var nas Detail
	for _, d := range v.Details {
		if d.ID == "192.168.1.20" {
			nas = d
		}
	}
	if len(nas.Services) != 1 || !strings.Contains(nas.Services[0], "445/tcp") {
		t.Errorf("services = %v, want the open port", nas.Services)
	}
	if len(nas.Findings) != 1 || nas.Findings[0].ID != "STIK-A004" {
		t.Errorf("findings = %+v, want the SMB finding", nas.Findings)
	}
}

// TestMapScriptIsValidJavaScript parses the inline script with node when it is
// available. The map's layout code can't be exercised by `go test` — this at
// least stops a syntax error from shipping in a report nobody can open.
// Skipped, not failed, where node isn't installed: CI for a Go project should
// not depend on a JS runtime.
func TestMapScriptIsValidJavaScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping the inline-script syntax check")
	}

	g, hosts, findings := sampleGraph(t)
	frag, err := Fragment(ViewFrom(g, hosts, findings))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	script := between(string(frag), "<script>", "</script>")
	if strings.TrimSpace(script) == "" {
		t.Fatal("no inline script found in the fragment")
	}

	path := filepath.Join(t.TempDir(), "map.js")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "--check", path).CombinedOutput()
	if err != nil {
		t.Fatalf("map script is not valid JavaScript: %v\n%s", err, out)
	}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
