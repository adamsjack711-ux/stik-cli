// Package alert delivers a stik event — a new device, or a possible rogue DHCP
// server — to one or more sinks. A desktop toast is useless on a headless box,
// which is exactly where a passive watcher wants to live, so alongside the
// native desktop notifier stik can POST to an ntfy topic or an arbitrary
// webhook. The daemon's whole job is to reach you; this is how it reaches you
// when you're not sitting at the machine.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/notify"
)

// Kind classifies an alert. It rides through to the webhook JSON as "event".
type Kind string

const (
	KindNewDevice Kind = "new_device"
	KindRogueDHCP Kind = "rogue_dhcp"
	KindARPSpoof  Kind = "arp_spoof"
)

// Event is a self-contained alert payload: JSON for a webhook, a title+body
// for a human notifier. It carries everything a downstream consumer needs so
// no sink has to reach back into stik's internals.
type Event struct {
	Kind      Kind      `json:"event"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip,omitempty"`
	Name      string    `json:"name,omitempty"` // Display(): user-given name or derived label
	Vendor    string    `json:"vendor,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Private   bool      `json:"private,omitempty"` // randomized (locally-administered) MAC
	FirstSeen time.Time `json:"first_seen"`
	Interface string    `json:"interface,omitempty"`

	// Set only for KindARPSpoof: the MAC/name that previously held Event.IP,
	// which Event.MAC has now taken over.
	PrevMAC  string `json:"prev_mac,omitempty"`
	PrevName string `json:"prev_name,omitempty"`
}

// Title is the one-line headline. Kept ASCII so it's safe in an HTTP header
// (ntfy carries the title that way).
func (e Event) Title() string {
	switch e.Kind {
	case KindRogueDHCP:
		return "Possible rogue DHCP server"
	case KindARPSpoof:
		return "Possible ARP spoofing"
	default:
		return "New device on your network"
	}
}

// Body is the human-readable detail line.
func (e Event) Body() string {
	if e.Kind == KindARPSpoof {
		who := e.Name
		if who == "" {
			who = e.MAC
		}
		s := e.IP + " is now claimed by " + who + " (" + e.MAC + ")"
		prev := e.PrevName
		if prev == "" {
			prev = e.PrevMAC
		}
		if prev != "" {
			s += " · was " + prev
		}
		return s
	}
	parts := []string{e.Name}
	if e.Name == "" {
		parts[0] = e.MAC
	}
	if e.IP != "" {
		parts = append(parts, e.IP)
	}
	if e.Hostname != "" {
		parts = append(parts, e.Hostname)
	}
	if e.Private {
		parts = append(parts, "randomized MAC")
	}
	if e.Kind == KindRogueDHCP {
		parts = append(parts, "handing out DHCP leases")
	}
	if !e.FirstSeen.IsZero() {
		parts = append(parts, "first seen "+e.FirstSeen.Format("15:04"))
	}
	return strings.Join(parts, " · ")
}

// Sink is one place an event can be delivered.
type Sink interface {
	Deliver(Event) error
	String() string // short name for logs, e.g. "desktop" or "ntfy:home-alerts"
}

// Notifier fans an event out to every configured sink, best-effort: one sink
// failing never stops the others.
type Notifier struct {
	sinks []Sink
}

// Sinks builds a Notifier from a list of specs. An empty list defaults to the
// desktop notifier, preserving stik's original behavior.
func Sinks(specs []string) (Notifier, error) {
	if len(specs) == 0 {
		specs = []string{"desktop"}
	}
	var sinks []Sink
	for _, spec := range specs {
		s, err := Parse(spec)
		if err != nil {
			return Notifier{}, err
		}
		sinks = append(sinks, s)
	}
	return Notifier{sinks: sinks}, nil
}

// Deliver sends the event to every sink and returns one error per failure
// (empty when all succeeded).
func (n Notifier) Deliver(e Event) []error {
	var errs []error
	for _, s := range n.sinks {
		if err := s.Deliver(e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.String(), err))
		}
	}
	return errs
}

// Describe lists the configured sinks for a startup banner.
func (n Notifier) Describe() string {
	names := make([]string, len(n.sinks))
	for i, s := range n.sinks {
		names[i] = s.String()
	}
	return strings.Join(names, ", ")
}

// Parse turns one --notify spec into a Sink:
//
//	desktop                     native desktop notification (the default)
//	ntfy://[server/]topic       POST to an ntfy topic (server defaults to ntfy.sh)
//	webhook://<http-url>        POST the event as JSON
//	http://… or https://…       shorthand for a webhook
func Parse(spec string) (Sink, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "", spec == "desktop":
		return desktopSink{}, nil
	case strings.HasPrefix(spec, "ntfy://"), strings.HasPrefix(spec, "ntfys://"):
		return parseNtfy(spec)
	case strings.HasPrefix(spec, "webhook://"):
		return newWebhook(strings.TrimPrefix(spec, "webhook://"))
	case strings.HasPrefix(spec, "http://"), strings.HasPrefix(spec, "https://"):
		return newWebhook(spec)
	default:
		return nil, fmt.Errorf("unknown notify target %q — want desktop, ntfy://[server/]topic, or an http(s) webhook URL", spec)
	}
}

func defaultClient() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

// --- desktop ---

type desktopSink struct{}

func (desktopSink) Deliver(e Event) error { return notify.Send(e.Title(), e.Body()) }
func (desktopSink) String() string        { return "desktop" }

// --- webhook ---

type webhookSink struct {
	url    string
	client *http.Client
}

func newWebhook(raw string) (Sink, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid webhook URL %q", raw)
	}
	return webhookSink{url: raw, client: defaultClient()}, nil
}

func (w webhookSink) Deliver(e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "stik")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (w webhookSink) String() string { return "webhook:" + w.url }

// --- ntfy ---

type ntfySink struct {
	postURL string
	topic   string
	client  *http.Client
}

func parseNtfy(spec string) (Sink, error) {
	rest := strings.TrimPrefix(spec, "ntfy://")
	rest = strings.TrimPrefix(rest, "ntfys://")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return nil, fmt.Errorf("ntfy spec needs a topic: ntfy://[server/]topic")
	}
	server, topic := "ntfy.sh", rest
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		server, topic = rest[:i], rest[i+1:]
	}
	if server == "" || topic == "" {
		return nil, fmt.Errorf("ntfy spec needs a topic: ntfy://[server/]topic")
	}
	return ntfySink{postURL: "https://" + server + "/" + topic, topic: topic, client: defaultClient()}, nil
}

func (n ntfySink) Deliver(e Event) error {
	req, err := http.NewRequest(http.MethodPost, n.postURL, strings.NewReader(e.Body()))
	if err != nil {
		return err
	}
	req.Header.Set("Title", e.Title())
	if e.Kind == KindRogueDHCP || e.Kind == KindARPSpoof {
		req.Header.Set("Priority", "urgent")
		req.Header.Set("Tags", "rotating_light")
	} else {
		req.Header.Set("Tags", "bell")
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n ntfySink) String() string { return "ntfy:" + n.topic }
