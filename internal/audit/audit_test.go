package audit

import (
	"strings"
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

func open(port int, mut ...func(*model.Service)) model.Service {
	s := model.Service{Port: port, Proto: "tcp", State: model.StateOpen}
	for _, m := range mut {
		m(&s)
	}
	return s
}

func hostWith(ip string, svcs ...model.Service) model.Host {
	return model.Host{IP: ip, Up: true, Services: svcs}
}

// ids returns the rule ids that fired, for exact-set assertions.
func ids(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func hasID(findings []model.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestExposedServiceRules(t *testing.T) {
	tests := []struct {
		name string
		svc  model.Service
		id   string
		sev  model.Severity
	}{
		{"telnet", open(23), "STIK-A001", model.SevHigh},
		{"rdp", open(3389), "STIK-A002", model.SevHigh},
		{"smb", open(445), "STIK-A004", model.SevHigh},
		{"redis", open(6379), "STIK-A005", model.SevHigh},
		{"mongo", open(27017), "STIK-A006", model.SevHigh},
		{"docker api", open(2375), "STIK-A009", model.SevCritical},
		{"ftp", open(21), "STIK-A020", model.SevMedium},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate([]model.Host{hostWith("192.168.1.10", tc.svc)})
			if len(got) != 1 {
				t.Fatalf("findings = %v, want exactly %s", ids(got), tc.id)
			}
			if got[0].ID != tc.id || got[0].Severity != tc.sev {
				t.Errorf("finding = %s/%s, want %s/%s", got[0].ID, got[0].Severity, tc.id, tc.sev)
			}
			if got[0].Host != "192.168.1.10" || got[0].Port != tc.svc.Port {
				t.Errorf("finding located at %s:%d, want 192.168.1.10:%d", got[0].Host, got[0].Port, tc.svc.Port)
			}
			if got[0].Evidence == "" || got[0].Fix == "" {
				t.Error("every finding needs evidence and a fix")
			}
		})
	}
}

func TestBenignServiceIsSilent(t *testing.T) {
	got := Evaluate([]model.Host{hostWith("192.168.1.10",
		open(22, func(s *model.Service) { s.Product = "OpenSSH"; s.Version = "9.6p1"; s.Banner = "SSH-2.0-OpenSSH_9.6p1" }),
		open(443, func(s *model.Service) {
			s.TLS = &model.TLSInfo{Version: "TLS 1.3", Subject: "nas.local", Issuer: "Internal CA"}
		}),
	)})
	if len(got) != 0 {
		t.Errorf("current SSH and a CA-issued TLS 1.3 service should be quiet, got %v", ids(got))
	}
}

func TestClosedPortsNeverFire(t *testing.T) {
	svc := model.Service{Port: 23, Proto: "tcp", State: model.StateClosed}
	if got := Evaluate([]model.Host{hostWith("192.168.1.10", svc)}); len(got) != 0 {
		t.Errorf("a closed port must not produce findings, got %v", ids(got))
	}
	svc.State = model.StateFiltered
	if got := Evaluate([]model.Host{hostWith("192.168.1.10", svc)}); len(got) != 0 {
		t.Errorf("a filtered port must not produce findings, got %v", ids(got))
	}
}

func TestTLSRules(t *testing.T) {
	tests := []struct {
		name    string
		tls     model.TLSInfo
		wantID  string
		wantNot string
	}{
		{"obsolete version", model.TLSInfo{Version: "TLS 1.0", Subject: "old.local", Issuer: "Internal CA"}, "STIK-A031", ""},
		{"expired", model.TLSInfo{Version: "TLS 1.2", Subject: "x.local", Issuer: "x.local", SelfSigned: true, Expired: true, NotAfter: "2020-01-01T00:00:00Z"}, "STIK-A032", "STIK-A033"},
		{"self-signed", model.TLSInfo{Version: "TLS 1.2", Subject: "nas.local", Issuer: "nas.local", SelfSigned: true}, "STIK-A033", "STIK-A032"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tlsInfo := tc.tls
			got := Evaluate([]model.Host{hostWith("10.0.0.5",
				open(8443, func(s *model.Service) { s.TLS = &tlsInfo }))})
			if !hasID(got, tc.wantID) {
				t.Errorf("findings = %v, want %s", ids(got), tc.wantID)
			}
			if tc.wantNot != "" && hasID(got, tc.wantNot) {
				t.Errorf("findings = %v, should not include %s", ids(got), tc.wantNot)
			}
		})
	}
}

func TestPlaintextRuleSkipsTLSWrappedService(t *testing.T) {
	// imaps on 143 is unusual but legal; if TLS is up, the plaintext rule is wrong.
	got := Evaluate([]model.Host{hostWith("10.0.0.5",
		open(143, func(s *model.Service) { s.TLS = &model.TLSInfo{Version: "TLS 1.3", Subject: "m.local", Issuer: "CA"} }))})
	if hasID(got, "STIK-A022") {
		t.Errorf("plaintext IMAP rule fired on a TLS-wrapped service: %v", ids(got))
	}
}

func TestAdminPanelOverPlainHTTP(t *testing.T) {
	got := Evaluate([]model.Host{hostWith("192.168.1.1",
		open(80, func(s *model.Service) { s.Banner = "Router Admin Login" }))})
	if !hasID(got, "STIK-A030") {
		t.Fatalf("findings = %v, want STIK-A030", ids(got))
	}
	// The same page behind TLS is not a plaintext-admin finding.
	got = Evaluate([]model.Host{hostWith("192.168.1.1",
		open(443, func(s *model.Service) {
			s.Banner = "Router Admin Login"
			s.TLS = &model.TLSInfo{Version: "TLS 1.3", Subject: "r.local", Issuer: "CA"}
		}))})
	if hasID(got, "STIK-A030") {
		t.Errorf("plain-HTTP admin rule fired on an HTTPS page: %v", ids(got))
	}
}

func TestStaleVersionAndBannerLeak(t *testing.T) {
	got := Evaluate([]model.Host{hostWith("192.168.1.7",
		open(22, func(s *model.Service) {
			s.Product, s.Version = "OpenSSH", "7.4"
			s.Banner = "SSH-2.0-OpenSSH_7.4 Debian-10"
		}))})
	if !hasID(got, "STIK-A040") {
		t.Errorf("findings = %v, want the stale-version finding", ids(got))
	}
	if !hasID(got, "STIK-A041") {
		t.Errorf("findings = %v, want the banner-leak finding", ids(got))
	}

	// A current version of the same product stays quiet.
	got = Evaluate([]model.Host{hostWith("192.168.1.7",
		open(22, func(s *model.Service) { s.Product, s.Version = "OpenSSH", "9.6p1" }))})
	if hasID(got, "STIK-A040") {
		t.Errorf("OpenSSH 9.6p1 is not behind the 9.0 baseline: %v", ids(got))
	}
}

func TestOlderThan(t *testing.T) {
	tests := []struct {
		have, min string
		want      bool
	}{
		{"7.4", "9.0", true},
		{"9.6p1", "9.0", false},
		{"10.0", "9.0", false}, // numeric, not lexical
		{"1.24.0", "1.24", false},
		{"1.23.4", "1.24", true},
		{"2.4.41", "2.4.55", true},
		{"", "9.0", false},
		{"nonsense", "9.0", false},
	}
	for _, tc := range tests {
		if got := olderThan(tc.have, tc.min); got != tc.want {
			t.Errorf("olderThan(%q, %q) = %v, want %v", tc.have, tc.min, got, tc.want)
		}
	}
}

func TestFindingsRankedWorstFirst(t *testing.T) {
	report := Report{Findings: Evaluate([]model.Host{
		hostWith("192.168.1.20", open(21), open(2375)),
		hostWith("192.168.1.10", open(23)),
	})}
	got := report.Findings
	if len(got) != 3 {
		t.Fatalf("findings = %v, want 3", ids(got))
	}
	if got[0].Severity != model.SevCritical || got[1].Severity != model.SevHigh || got[2].Severity != model.SevMedium {
		t.Errorf("order = %v, want critical, high, medium", []model.Severity{got[0].Severity, got[1].Severity, got[2].Severity})
	}
	if report.Worst() != model.SevCritical {
		t.Errorf("worst = %s, want critical", report.Worst())
	}
	if c := report.Counts(); c[model.SevCritical] != 1 || c[model.SevHigh] != 1 || c[model.SevMedium] != 1 {
		t.Errorf("counts = %v, want one of each", c)
	}
}

func TestEvaluateIsDeterministic(t *testing.T) {
	hosts := []model.Host{hostWith("192.168.1.10", open(23), open(445), open(21), open(3389))}
	first := ids(Evaluate(hosts))
	for i := 0; i < 20; i++ {
		if got := ids(Evaluate(hosts)); !equal(got, first) {
			t.Fatalf("run %d = %v, want the stable order %v", i, got, first)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReportNameFallsBackToIP(t *testing.T) {
	r := Report{Names: map[string]string{"192.168.1.20": "Jack's NAS"}}
	if got := r.Name("192.168.1.20"); got != "Jack's NAS" {
		t.Errorf("Name = %q, want the device name", got)
	}
	if got := r.Name("192.168.1.99"); got != "192.168.1.99" {
		t.Errorf("Name = %q, want the bare IP", got)
	}
}

func openUDP(port int, mut ...func(*model.Service)) model.Service {
	s := model.Service{Port: port, Proto: "udp", State: model.StateOpen}
	for _, m := range mut {
		m(&s)
	}
	return s
}

func TestUDPExposureRules(t *testing.T) {
	tests := []struct {
		name string
		svc  model.Service
		id   string
		sev  model.Severity
	}{
		{"snmp answered public", openUDP(161), "STIK-A050", model.SevHigh},
		{"ipmi bmc", openUDP(623), "STIK-A051", model.SevHigh},
		{"memcached over udp", openUDP(11211), "STIK-A052", model.SevHigh},
		{"ssdp", openUDP(1900), "STIK-A053", model.SevMedium},
		{"tftp", openUDP(69), "STIK-A054", model.SevMedium},
		{"open resolver", openUDP(53), "STIK-A055", model.SevMedium},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate([]model.Host{hostWith("192.168.1.10", tc.svc)})
			if len(got) != 1 || got[0].ID != tc.id || got[0].Severity != tc.sev {
				t.Fatalf("findings = %v, want %s/%s", ids(got), tc.id, tc.sev)
			}
			if !strings.Contains(got[0].Evidence, "/udp") {
				t.Errorf("evidence = %q, should name the protocol", got[0].Evidence)
			}
		})
	}
}

func TestUDPAndTCPPortsAreDifferentServices(t *testing.T) {
	// 11211 over TCP is the memcached TCP rule; over UDP it is the amplification
	// rule. Firing both for one port would double-count and misdescribe.
	udp := Evaluate([]model.Host{hostWith("192.168.1.10", openUDP(11211))})
	if len(udp) != 1 || udp[0].ID != "STIK-A052" {
		t.Errorf("udp findings = %v, want only the UDP rule", ids(udp))
	}
	tcp := Evaluate([]model.Host{hostWith("192.168.1.10", open(11211))})
	if len(tcp) != 1 || tcp[0].ID != "STIK-A008" {
		t.Errorf("tcp findings = %v, want only the TCP rule", ids(tcp))
	}
}

func TestOpenFilteredUDPDoesNotFireRules(t *testing.T) {
	// open|filtered means we do not know whether anything is there. A finding
	// built on that would be a guess presented as an observation.
	svc := openUDP(161)
	svc.State = model.StateOpenFiltered
	if got := Evaluate([]model.Host{hostWith("192.168.1.10", svc)}); len(got) != 0 {
		t.Errorf("open|filtered produced findings: %v", ids(got))
	}
}
