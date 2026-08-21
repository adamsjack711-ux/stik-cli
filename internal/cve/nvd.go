package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// NVD's public API allows 5 requests per rolling 30 seconds without a key, and
// 50 with one. Exceeding it gets you blocked rather than throttled, so the
// client paces itself and never retries into a wall.
const (
	defaultBase  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	unkeyedPace  = 7 * time.Second
	keyedPace    = 800 * time.Millisecond
	requestLimit = 40 // CVEs per service; a service with more is already the story
)

// Vulnerability is one CVE as stik-net reports it: enough to judge, with a link
// for the rest. Severity is NVD's own CVSS rating, not our interpretation.
type Vulnerability struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW from CVSS
	Score       float64 `json:"score,omitempty"`
	Summary     string  `json:"summary,omitempty"`
	Published   string  `json:"published,omitempty"`
	URL         string  `json:"url"`
	MatchedCPE  string  `json:"matched_cpe,omitempty"`
	KnownRansom bool    `json:"known_ransomware_campaign,omitempty"`
}

// Client queries the NVD. The zero value is usable and unkeyed.
type Client struct {
	BaseURL string
	APIKey  string       // NVD_API_KEY; raises the rate limit
	HTTP    *http.Client // nil uses a 20s-timeout client
	Now     func() time.Time

	lastCall time.Time
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return defaultBase
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// pace sleeps as much as the rate limit requires. It is deliberately simple:
// the alternative to waiting is being blocked.
func (c *Client) pace(ctx context.Context) error {
	gap := unkeyedPace
	if c.APIKey != "" {
		gap = keyedPace
	}
	if c.lastCall.IsZero() {
		c.lastCall = c.now()
		return nil
	}
	wait := gap - c.now().Sub(c.lastCall)
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.lastCall = c.now()
	return nil
}

// Query asks NVD which CVEs match a CPE. An empty result is a real answer:
// nothing known matches this version.
func (c *Client) Query(ctx context.Context, cpe string) ([]Vulnerability, error) {
	if err := c.pace(ctx); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s?cpeName=%s&resultsPerPage=%d",
		c.base(), url.QueryEscape(cpe), requestLimit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "stik-net")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying NVD: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("NVD rate-limited this scan (HTTP %d) — set NVD_API_KEY for a higher limit", resp.StatusCode)
	default:
		return nil, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}

	var payload nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("reading NVD response: %w", err)
	}
	return payload.vulnerabilities(cpe), nil
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			CisaVulnerabilityName string `json:"cisaVulnerabilityName"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

func (r nvdResponse) vulnerabilities(cpe string) []Vulnerability {
	out := make([]Vulnerability, 0, len(r.Vulnerabilities))
	for _, item := range r.Vulnerabilities {
		v := Vulnerability{
			ID:         item.CVE.ID,
			Published:  item.CVE.Published,
			URL:        "https://nvd.nist.gov/vuln/detail/" + item.CVE.ID,
			MatchedCPE: cpe,
			// CISA names a CVE here when it is known to be used in ransomware
			// campaigns — the one signal worth surfacing above the score.
			KnownRansom: item.CVE.CisaVulnerabilityName != "",
		}
		for _, d := range item.CVE.Descriptions {
			if d.Lang == "en" {
				v.Summary = trim(d.Value, 240)
				break
			}
		}
		v.Severity, v.Score = pickMetric(item.CVE.Metrics.V31, item.CVE.Metrics.V30, item.CVE.Metrics.V2)
		out = append(out, v)
	}
	// Worst first: a list of forty CVEs is only useful if the top of it matters.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func pickMetric(sets ...[]nvdMetric) (string, float64) {
	for _, set := range sets {
		if len(set) == 0 {
			continue
		}
		m := set[0]
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		return strings.ToUpper(sev), m.CVSSData.BaseScore
	}
	return "", 0
}

func trim(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "…"
}
