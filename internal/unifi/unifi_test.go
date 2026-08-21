package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// The fixtures follow the classic private API's documented shapes: a
// {"meta":{"rc":"ok"},"data":[…]} envelope, VLAN ids that are a number on some
// controller versions and a string on others, and the three different spellings
// UniFi has used for network isolation.

const networkConfJSON = `{"meta":{"rc":"ok"},"data":[
 {"_id":"n1","name":"LAN","purpose":"corporate","vlan":"","ip_subnet":"192.168.1.0/24","enabled":true,
  "dhcpd_enabled":true,"dhcpd_start":"192.168.1.100","dhcpd_stop":"192.168.1.200"},
 {"_id":"n2","name":"Guest","purpose":"guest","vlan":20,"ip_subnet":"192.168.20.0/24","enabled":true,
  "is_guest":true,"network_isolation_enabled":false},
 {"_id":"n3","name":"IoT","purpose":"corporate","vlan":"30","ip_subnet":"192.168.30.0/24","enabled":true,
  "isolation":true},
 {"_id":"n4","name":"WAN","purpose":"wan","ip_subnet":"0.0.0.0/0"}
]}`

const deviceJSON = `{"meta":{"rc":"ok"},"data":[
 {"mac":"aa:bb:cc:00:00:01","name":"Dream Machine","model":"UDMPROSE","type":"udm","state":1,"adopted":true},
 {"mac":"aa:bb:cc:00:00:02","name":"Office Switch","model":"USL8LP","type":"usw","state":1,"adopted":true},
 {"mac":"aa:bb:cc:00:00:03","name":"Loft AP","model":"U6LR","type":"uap","state":0,"adopted":true}
]}`

const staJSON = `{"meta":{"rc":"ok"},"data":[
 {"mac":"11:22:33:44:55:01","hostname":"nas","name":"Jack's NAS","ip":"192.168.1.20","network_id":"n1","is_wired":true},
 {"mac":"11:22:33:44:55:02","hostname":"iphone","ip":"192.168.20.51","network":"Guest","is_guest":true},
 {"mac":"11:22:33:44:55:03","oui":"Espressif","ip":"192.168.30.11","network_id":"n3"},
 {"mac":"11:22:33:44:55:04","hostname":"mystery","ip":"10.9.9.9"}
]}`

const firewallJSON = `{"meta":{"rc":"ok"},"data":[
 {"_id":"f1","name":"Block IoT to LAN","enabled":true,"action":"drop","ruleset":"LAN_IN","rule_index":2000}
]}`

// controller stands in for a UniFi box: login, then the four read endpoints.
func controller(t *testing.T, opts ...func(*stub)) (*httptest.Server, *stub) {
	t.Helper()
	s := &stub{
		login:    http.StatusOK,
		networks: networkConfJSON,
		devices:  deviceJSON,
		stations: staJSON,
		firewall: firewallJSON,
	}
	for _, o := range opts {
		o(s)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.methods = append(s.methods, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/auth/login"):
			body, _ := io.ReadAll(r.Body)
			s.loginBody = string(body)
			if s.login != http.StatusOK {
				w.WriteHeader(s.login)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		case strings.HasSuffix(r.URL.Path, "/rest/networkconf"):
			_, _ = w.Write([]byte(s.networks))
		case strings.HasSuffix(r.URL.Path, "/stat/device"):
			_, _ = w.Write([]byte(s.devices))
		case strings.HasSuffix(r.URL.Path, "/stat/sta"):
			_, _ = w.Write([]byte(s.stations))
		case strings.HasSuffix(r.URL.Path, "/rest/firewallrule"):
			if s.firewall == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(s.firewall))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

type stub struct {
	login                                 int
	networks, devices, stations, firewall string
	methods                               []string
	loginBody                             string
}

func loggedIn(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL, "default", true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background(), "admin", "hunter2", ""); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return c
}

func TestFetchAndBuildTheSegmentationMap(t *testing.T) {
	srv, _ := controller(t)
	snap, err := loggedIn(t, srv).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	m := Build("default", snap)

	// The WAN is not a segment of the LAN and must not appear as one.
	if len(m.Segments) != 3 {
		var names []string
		for _, s := range m.Segments {
			names = append(names, s.Network.Name)
		}
		t.Fatalf("segments = %v, want LAN/Guest/IoT without the WAN", names)
	}

	byName := map[string]Segment{}
	for _, s := range m.Segments {
		byName[s.Network.Name] = s
	}
	// Matched by network_id.
	if got := byName["LAN"].Stations; len(got) != 1 || got[0].Display() != "Jack's NAS" {
		t.Errorf("LAN stations = %+v", got)
	}
	// Matched by network name, because the controller populated that instead.
	if got := byName["Guest"].Stations; len(got) != 1 || got[0].IP != "192.168.20.51" {
		t.Errorf("Guest stations = %+v", got)
	}
	// A station the controller did not attribute is kept, not dropped.
	if len(m.Unassigned) != 1 || m.Unassigned[0].IP != "10.9.9.9" {
		t.Errorf("unassigned = %+v, want the one unattributed station", m.Unassigned)
	}
}

func TestIsolationIsReadInAllThreeSpellings(t *testing.T) {
	// UniFi has spelled this three ways across versions; missing it on one
	// firmware would mean reporting an isolated network as open.
	tests := []struct {
		name string
		net  Network
		want bool
	}{
		{"modern flag", Network{Purpose: "corporate", Isolation: true}, true},
		{"legacy flag", Network{Purpose: "corporate", IsolationAlt: true}, true},
		// is_guest marks a guest network; it does NOT mean the network is
		// isolated. Treating it as isolation would report an open guest network
		// as walled off — the error direction that gets someone hurt.
		{"is_guest is not an isolation flag", Network{Purpose: "guest", IsGuest: true}, false},
		{"plain corporate", Network{Purpose: "corporate"}, false},
		{"guest with isolation off", Network{Purpose: "guest"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.net.Isolated(); got != tc.want {
				t.Errorf("Isolated() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGuestNetworkWithoutIsolationIsTheHeadline(t *testing.T) {
	srv, _ := controller(t)
	snap, _ := loggedIn(t, srv).Fetch(context.Background())
	m := Build("default", snap)

	concerns := strings.Join(m.Concerns(), " | ")
	if !strings.Contains(concerns, "Guest") || !strings.Contains(concerns, "isolation off") {
		t.Errorf("concerns = %q, want the un-isolated guest network called out", concerns)
	}
}

func TestVLANIdSurvivesBothEncodings(t *testing.T) {
	// Some controller versions send a number, others a string.
	if got := vlanString(float64(20)); got != "20" {
		t.Errorf("numeric vlan = %q", got)
	}
	if got := vlanString("30"); got != "30" {
		t.Errorf("string vlan = %q", got)
	}
	if got := vlanString(nil); got != "" {
		t.Errorf("absent vlan = %q", got)
	}
	if got := vlanString(float64(0)); got != "" {
		t.Errorf("vlan 0 means untagged, got %q", got)
	}
}

func TestMissingFirewallDegradesAndSaysSo(t *testing.T) {
	// UniFi 10's zone-based firewall has no read API. A map that refuses to draw
	// would be worse than one that reports the gap.
	srv, _ := controller(t, func(s *stub) { s.firewall = "" })
	snap, err := loggedIn(t, srv).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch should survive a missing firewall endpoint: %v", err)
	}
	m := Build("default", snap)
	if m.FirewallOK {
		t.Error("FirewallOK should be false when no rules were readable")
	}
	if !strings.Contains(strings.Join(m.Concerns(), " "), "no read API") {
		t.Errorf("the gap should be stated: %v", m.Concerns())
	}
	if len(m.Segments) == 0 {
		t.Error("the rest of the map should still be built")
	}
}

func TestTheClientOnlyEverIssuesGETsAfterLogin(t *testing.T) {
	// The guarantee is structural: no write method is exposed, and the CSRF
	// token a controller needs for a change is never read.
	srv, s := controller(t)
	if _, err := loggedIn(t, srv).Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, m := range s.methods {
		if strings.HasPrefix(m, "POST") && !strings.Contains(m, "/api/auth/login") {
			t.Errorf("unexpected write: %s", m)
		}
		if strings.HasPrefix(m, "PUT") || strings.HasPrefix(m, "DELETE") || strings.HasPrefix(m, "PATCH") {
			t.Errorf("unexpected write: %s", m)
		}
	}
}

func TestTwoFactorIsItsOwnAnswer(t *testing.T) {
	srv, _ := controller(t, func(s *stub) { s.login = 499 })
	c, _ := New(srv.URL, "default", true)
	err := c.Login(context.Background(), "admin", "hunter2", "")
	var twoFA TwoFactorError
	if err == nil || !errorsAs(err, &twoFA) {
		t.Fatalf("HTTP 499 should surface as a 2FA prompt, got %v", err)
	}
	if !strings.Contains(err.Error(), "--token") {
		t.Errorf("the error should say how to proceed: %v", err)
	}
}

func TestBadCredentialsAreDistinctFromABoxBeingDown(t *testing.T) {
	srv, _ := controller(t, func(s *stub) { s.login = http.StatusUnauthorized })
	c, _ := New(srv.URL, "default", true)
	err := c.Login(context.Background(), "admin", "wrong", "")
	var authErr AuthError
	if err == nil || !errorsAs(err, &authErr) {
		t.Fatalf("401 should be an AuthError, got %v", err)
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("error = %v, want it to name the actual problem", err)
	}
}

func TestLoginSendsTheTokenWhenGiven(t *testing.T) {
	srv, s := controller(t)
	c, _ := New(srv.URL, "default", true)
	if err := c.Login(context.Background(), "admin", "hunter2", "123456"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(s.loginBody), &body); err != nil {
		t.Fatalf("login body: %v", err)
	}
	if body["token"] != "123456" {
		t.Errorf("token = %v, want it forwarded", body["token"])
	}
	if body["remember"] != true {
		t.Errorf("remember = %v", body["remember"])
	}
}

func TestBareHostGetsHTTPS(t *testing.T) {
	c, err := New("192.168.1.1", "", false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.BaseURL != "https://192.168.1.1" {
		t.Errorf("BaseURL = %q, want https", c.BaseURL)
	}
	if c.Site != "default" {
		t.Errorf("Site = %q, want the default site", c.Site)
	}
}

func TestWriteTextLeadsWithWhatMatters(t *testing.T) {
	srv, _ := controller(t)
	snap, _ := loggedIn(t, srv).Fetch(context.Background())

	var buf bytes.Buffer
	WriteText(&buf, ui.Style{}, Build("default", snap))
	out := buf.String()

	for _, want := range []string{
		"UniFi segmentation",
		"isolation off", // the concern, above the inventory
		"Guest",         // networks
		"IoT",
		"isolated from the other networks",
		"Jack's NAS", // stations
		"gateway",    // infrastructure, in plain words
		"access point",
		"Block IoT to LAN", // firewall rules when readable
		"read-only",        // the guarantee, restated where it is read
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}

	concernAt := strings.Index(out, "isolation off")
	inventoryAt := strings.Index(out, "Jack's NAS")
	if concernAt > inventoryAt {
		t.Error("the concern should come before the inventory")
	}
}

// errorsAs is errors.As, spelled locally to keep the import list honest about
// what this file uses.
func errorsAs(err error, target any) bool {
	switch t := target.(type) {
	case *TwoFactorError:
		var e TwoFactorError
		if ok := asType(err, &e); ok {
			*t = e
			return true
		}
	case *AuthError:
		var e AuthError
		if ok := asType(err, &e); ok {
			*t = e
			return true
		}
	}
	return false
}

func asType[T error](err error, out *T) bool {
	if v, ok := err.(T); ok {
		*out = v
		return true
	}
	return false
}

func TestGuestByFlagAloneIsStillAGuestNetwork(t *testing.T) {
	// Some controllers set is_guest without setting purpose, and a guest network
	// that goes unrecognised is a guest network whose isolation nobody checks.
	n := Network{Name: "Visitors", IsGuest: true}
	if !n.IsGuestNetwork() {
		t.Error("is_guest alone should mark a guest network")
	}
	if n.Isolated() {
		t.Error("...but it must not imply isolation")
	}
	notes := strings.Join(notesFor(n), " ")
	if !strings.Contains(notes, "without isolation") {
		t.Errorf("notes = %q, want the isolation gap called out", notes)
	}
}

func TestIsolatedGuestNetworkRaisesNoConcern(t *testing.T) {
	m := Map{Segments: []Segment{{Network: Network{Name: "Guest", Purpose: "guest", Isolation: true}}}, FirewallOK: true}
	if len(m.Concerns()) != 0 {
		t.Errorf("a properly isolated guest network is fine: %v", m.Concerns())
	}
}
