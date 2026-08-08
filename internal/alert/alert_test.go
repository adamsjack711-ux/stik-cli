package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseSpecs(t *testing.T) {
	cases := []struct {
		spec    string
		want    string // expected Sink.String()
		wantErr bool
	}{
		{"desktop", "desktop", false},
		{"", "desktop", false},
		{"ntfy://my-topic", "ntfy:my-topic", false},
		{"ntfy://ntfy.example.com/alerts", "ntfy:alerts", false},
		{"webhook://https://hooks.example.com/x", "webhook:https://hooks.example.com/x", false},
		{"https://hooks.example.com/x", "webhook:https://hooks.example.com/x", false},
		{"ntfy://", "", true},
		{"webhook://not-a-url", "", true},
		{"carrier-pigeon", "", true},
	}
	for _, c := range cases {
		s, err := Parse(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q): expected error, got sink %v", c.spec, s)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error %v", c.spec, err)
			continue
		}
		if s.String() != c.want {
			t.Errorf("Parse(%q).String() = %q, want %q", c.spec, s.String(), c.want)
		}
	}
}

func sampleEvent() Event {
	return Event{
		Kind:      KindNewDevice,
		MAC:       "a4:83:e7:2f:11:0c",
		IP:        "192.168.1.42",
		Name:      "Apple iPhone",
		Vendor:    "Apple, Inc.",
		Private:   true,
		FirstSeen: time.Date(2026, 8, 8, 15, 2, 0, 0, time.UTC),
	}
}

func TestWebhookDeliverPostsJSON(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sink, err := newWebhook(srv.URL)
	if err != nil {
		t.Fatalf("newWebhook: %v", err)
	}
	if err := sink.Deliver(sampleEvent()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	var got Event
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("payload not JSON: %v (%s)", err, gotBody)
	}
	if got.Kind != KindNewDevice || got.MAC != "a4:83:e7:2f:11:0c" || !got.Private {
		t.Errorf("round-tripped event wrong: %+v", got)
	}
}

func TestWebhookDeliverErrorsOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	sink, _ := newWebhook(srv.URL)
	if err := sink.Deliver(sampleEvent()); err == nil {
		t.Error("expected error on HTTP 500, got nil")
	}
}

func TestNtfyDeliverSendsTitleAndBody(t *testing.T) {
	var gotTitle, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Point an ntfy sink straight at the test server (same package, so we can
	// build it directly rather than through Parse's https://ntfy.sh default).
	sink := ntfySink{postURL: srv.URL + "/home-alerts", topic: "home-alerts", client: defaultClient()}
	ev := sampleEvent()
	if err := sink.Deliver(ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if gotTitle != ev.Title() {
		t.Errorf("Title header = %q, want %q", gotTitle, ev.Title())
	}
	if gotBody != ev.Body() {
		t.Errorf("body = %q, want %q", gotBody, ev.Body())
	}
}

func TestEventBodyMentionsRandomizedMAC(t *testing.T) {
	e := sampleEvent()
	if got := e.Body(); !contains(got, "randomized MAC") {
		t.Errorf("Body() = %q, want it to mention randomized MAC", got)
	}
}

func TestRogueDHCPTitleAndBody(t *testing.T) {
	e := sampleEvent()
	e.Kind = KindRogueDHCP
	if e.Title() != "Possible rogue DHCP server" {
		t.Errorf("rogue title = %q", e.Title())
	}
	if !contains(e.Body(), "handing out DHCP leases") {
		t.Errorf("rogue body = %q, want DHCP mention", e.Body())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
