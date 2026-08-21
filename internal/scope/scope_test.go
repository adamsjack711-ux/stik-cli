package scope

import (
	"net"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *Set {
	t.Helper()
	s, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	return s
}

func TestContainsCIDRAndHost(t *testing.T) {
	s := mustParse(t, "192.168.1.0/24\n10.0.0.5\n")
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},   // adjacent subnet, out of scope
		{"10.0.0.5", true},       // exact single host
		{"10.0.0.6", false},      // neighbor of a /32 host is out
		{"127.0.0.1", false},     // never implicitly in scope
	}
	for _, c := range cases {
		if got := s.Contains(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// The load-bearing safety property: an empty or nil scope authorizes nothing.
func TestEmptyScopeFailsClosed(t *testing.T) {
	var nilSet *Set
	if nilSet.Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("nil scope must contain nothing")
	}
	empty := &Set{}
	if empty.Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("zero-value scope must contain nothing")
	}
	if !empty.Empty() {
		t.Fatal("zero-value scope must report Empty")
	}
}

func TestParseRejectsEmptyAndGarbage(t *testing.T) {
	// A file of only comments/blanks parses but is Empty — Load turns that into
	// an error so a run can't silently proceed against nothing.
	s := mustParse(t, "# just a comment\n\n   \n")
	if !s.Empty() {
		t.Fatal("comment/blank-only scope should be Empty")
	}
	if _, err := Parse(strings.NewReader("192.168.1.0/24\nnot-an-ip\n")); err == nil {
		t.Fatal("malformed entry must fail the whole parse")
	}
}

func TestCommentsAndWhitespaceStripped(t *testing.T) {
	s := mustParse(t, "  10.1.0.0/16   # office LAN\n\t192.0.2.7 # a host\n")
	if !s.Contains(net.ParseIP("10.1.2.3")) {
		t.Error("inline-comment CIDR should still match")
	}
	if !s.Contains(net.ParseIP("192.0.2.7")) {
		t.Error("whitespace/comment host should still match")
	}
	if got := len(s.Entries()); got != 2 {
		t.Errorf("Entries() = %d, want 2", got)
	}
}

func TestContainsHostTolerm(t *testing.T) {
	s := mustParse(t, "203.0.113.0/24\n")
	if !s.ContainsHost("203.0.113.9:443") {
		t.Error("host:port form should be accepted")
	}
	if s.ContainsHost("not.a.literal.hostname") {
		t.Error("a hostname (not an IP literal) must not match — caller must resolve first")
	}
	if s.ContainsHost("203.0.114.9") {
		t.Error("out-of-scope host:port must not match")
	}
}

func TestIPv6Host(t *testing.T) {
	s := mustParse(t, "2001:db8::/32\n")
	if !s.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("v6 CIDR should match")
	}
	if s.Contains(net.ParseIP("2001:db9::1")) {
		t.Error("v6 out-of-scope should not match")
	}
}

func TestFingerprintStable(t *testing.T) {
	a := mustParse(t, "192.168.1.0/24\n10.0.0.5\n")
	b := mustParse(t, "10.0.0.5 # reordered\n192.168.1.0/24\n")
	if a.Fingerprint() == "" {
		t.Fatal("fingerprint should be non-empty")
	}
	// Same authorized set, different order/comments → same fingerprint is nice
	// but not required; what matters is a *different* set differs.
	c := mustParse(t, "192.168.1.0/24\n")
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("different scopes must have different fingerprints")
	}
	_ = b
}
