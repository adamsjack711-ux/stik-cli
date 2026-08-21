package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

func runAt(when string, hosts ...model.Host) Report {
	t, _ := time.Parse(time.RFC3339, when)
	return Report{StartedAt: t, Hosts: hosts, Findings: Evaluate(hosts)}
}

func changeKeys(changes []ServiceChange) []string {
	var out []string
	for _, c := range changes {
		out = append(out, c.Host+":"+itoa(c.Service.Port))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestDiffOfAnUnchangedNetworkIsEmpty(t *testing.T) {
	hosts := []model.Host{hostWith("192.168.1.20", open(445), open(22))}
	before := runAt("2026-08-20T10:00:00Z", hosts...)
	after := runAt("2026-08-21T10:00:00Z", hosts...)

	d := Diff(before, after)
	if !d.Empty() {
		t.Errorf("nothing changed, but got %+v", d)
	}
	// The same finding seen twice is continuity, not news.
	if len(d.NewFindings) != 0 {
		t.Errorf("re-observed findings should not be new: %v", ids(d.NewFindings))
	}
}

func TestDiffFindsANewlyOpenedPortAndItsFinding(t *testing.T) {
	before := runAt("2026-08-20T10:00:00Z", hostWith("192.168.1.20", open(22)))
	after := runAt("2026-08-21T10:00:00Z", hostWith("192.168.1.20", open(22), open(445)))

	d := Diff(before, after)
	if got := changeKeys(d.Opened); len(got) != 1 || got[0] != "192.168.1.20:445" {
		t.Errorf("opened = %v, want the new SMB port", got)
	}
	if len(d.Closed) != 0 {
		t.Errorf("closed = %v, want none", changeKeys(d.Closed))
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].ID != "STIK-A004" {
		t.Errorf("new findings = %v, want the SMB finding", ids(d.NewFindings))
	}
	if d.Worst() != model.SevHigh {
		t.Errorf("worst new = %q, want high", d.Worst())
	}
}

func TestDiffFindsAClosedPortAndAResolvedFinding(t *testing.T) {
	before := runAt("2026-08-20T10:00:00Z", hostWith("192.168.1.20", open(22), open(445)))
	after := runAt("2026-08-21T10:00:00Z", hostWith("192.168.1.20", open(22)))

	d := Diff(before, after)
	if got := changeKeys(d.Closed); len(got) != 1 || got[0] != "192.168.1.20:445" {
		t.Errorf("closed = %v, want the SMB port", got)
	}
	if len(d.ResolvedFindings) != 1 || d.ResolvedFindings[0].ID != "STIK-A004" {
		t.Errorf("resolved = %v, want the SMB finding", ids(d.ResolvedFindings))
	}
	// Nothing appeared, so a --fail-on gate must not trip.
	if d.Worst() != model.SevInfo {
		t.Errorf("worst new = %q, want info — a fix is not a regression", d.Worst())
	}
}

func TestDiffReportsNewAndVanishedHosts(t *testing.T) {
	before := runAt("2026-08-20T10:00:00Z", hostWith("192.168.1.20", open(22)))
	after := runAt("2026-08-21T10:00:00Z", hostWith("192.168.1.20", open(22)), hostWith("192.168.1.99", open(23)))

	d := Diff(before, after)
	if len(d.NewHosts) != 1 || d.NewHosts[0] != "192.168.1.99" {
		t.Errorf("new hosts = %v", d.NewHosts)
	}
	if len(d.NewFindings) != 1 || d.NewFindings[0].Host != "192.168.1.99" {
		t.Errorf("the new host's telnet finding should be new: %v", ids(d.NewFindings))
	}

	back := Diff(after, before)
	if len(back.GoneHosts) != 1 || back.GoneHosts[0] != "192.168.1.99" {
		t.Errorf("gone hosts = %v", back.GoneHosts)
	}
}

func TestVanishedHostDoesNotAlsoCountAsClosedPorts(t *testing.T) {
	// One event, reported once: the host left. Listing each of its ports as
	// "closed" would turn a single departure into a wall of noise.
	before := runAt("2026-08-20T10:00:00Z", hostWith("192.168.1.99", open(22), open(23), open(445)))
	after := runAt("2026-08-21T10:00:00Z")

	d := Diff(before, after)
	if len(d.GoneHosts) != 1 {
		t.Fatalf("gone hosts = %v, want the one host", d.GoneHosts)
	}
	if len(d.Closed) != 0 {
		t.Errorf("closed = %v, want none — the host itself is the event", changeKeys(d.Closed))
	}
}

func TestDiffOrdersChangesNumericallyByAddress(t *testing.T) {
	before := runAt("2026-08-20T10:00:00Z")
	after := runAt("2026-08-21T10:00:00Z",
		hostWith("192.168.1.10", open(22)),
		hostWith("192.168.1.9", open(22)),
		hostWith("192.168.1.2", open(22)))

	d := Diff(before, after)
	want := []string{"192.168.1.2", "192.168.1.9", "192.168.1.10"}
	for i := range want {
		if d.NewHosts[i] != want[i] {
			t.Fatalf("new hosts = %v, want %v", d.NewHosts, want)
		}
	}
}

func TestDiffSeverityGateIgnoresPreexistingFindings(t *testing.T) {
	// A high finding that was already there must not fail a change gate; only
	// what appeared since counts.
	hosts := []model.Host{hostWith("192.168.1.20", open(445))}
	d := Diff(runAt("2026-08-20T10:00:00Z", hosts...), runAt("2026-08-21T10:00:00Z", hosts...))
	if d.Worst() != model.SevInfo {
		t.Errorf("worst new = %q, want info for an unchanged high finding", d.Worst())
	}
}

func TestWriteDiffTextSaysNothingChanged(t *testing.T) {
	hosts := []model.Host{hostWith("192.168.1.20", open(22))}
	var buf bytes.Buffer
	WriteDiffText(&buf, ui.Style{}, Diff(runAt("2026-08-20T10:00:00Z", hosts...), runAt("2026-08-21T10:00:00Z", hosts...)))
	if !strings.Contains(buf.String(), "nothing changed") {
		t.Errorf("a quiet night should say so plainly:\n%s", buf.String())
	}
}

func TestWriteDiffTextShowsEachKindOfChange(t *testing.T) {
	before := runAt("2026-08-20T10:00:00Z", hostWith("192.168.1.20", open(22), open(21)))
	after := runAt("2026-08-21T10:00:00Z", hostWith("192.168.1.20", open(22), open(445)), hostWith("192.168.1.99", open(23)))
	after.Names = map[string]string{"192.168.1.99": "Jack's NAS"}

	var buf bytes.Buffer
	WriteDiffText(&buf, ui.Style{}, Diff(before, after))
	out := buf.String()

	for _, want := range []string{
		"+ host", "192.168.1.99", "Jack's NAS",
		"+ port", "192.168.1.20:445",
		"- port", "192.168.1.20:21",
		"new findings", "SMB reachable on the network",
		"no longer present", "FTP without transport encryption",
		"2026-08-20 10:00:00 → 2026-08-21 10:00:00",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output missing %q\n---\n%s", want, out)
		}
	}
}
