// Package unifi talks to a UniFi Network controller. It is the opposite of
// everything stik-net promises — active, authenticated, and aimed at a box that
// will happily let an admin change the network — which is exactly why it lives
// in its own binary rather than behind a flag on the passive watcher.
//
// It is read-only by construction: the client exposes GET and nothing else, and
// never asks for the CSRF token a UniFi controller requires before it will
// accept a write. A tool that cannot mint the token cannot make the change,
// which is a stronger guarantee than a promise not to.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Client is an authenticated session against one controller.
type Client struct {
	BaseURL  string // https://192.168.1.1 — the controller, not the site
	Site     string // "default" unless the controller was set up otherwise
	Insecure bool   // controllers ship self-signed certs; this is usually needed

	HTTP *http.Client
}

// TwoFactorError says the controller wants a 2FA token. UniFi answers HTTP 499
// for this, which is not a status anybody else uses, so it gets its own type.
type TwoFactorError struct{}

func (TwoFactorError) Error() string {
	return "this controller requires a 2FA token — pass --token <code> and try again"
}

// AuthError is a rejected login, kept distinct from a network failure so the
// CLI can tell someone their password is wrong rather than that the box is down.
type AuthError struct{ Status int }

func (e AuthError) Error() string {
	return fmt.Sprintf("the controller rejected those credentials (HTTP %d)", e.Status)
}

// New builds a client with a cookie jar, since UniFi authenticates by session
// cookie rather than a bearer token.
func New(baseURL, site string, insecure bool) (*Client, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("controller address %q: %w", baseURL, err)
	}
	if site == "" {
		site = "default"
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{}
	if insecure {
		// A UniFi controller presents a self-signed certificate by default. This
		// is a local box on a network the operator administers, and refusing to
		// talk to it would just push people to curl -k.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Site:     site,
		Insecure: insecure,
		HTTP:     &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: transport},
	}, nil
}

// Login authenticates. token may be empty; supply it when the controller
// answers with TwoFactorError.
func (c *Client) Login(ctx context.Context, username, password, token string) error {
	body := map[string]any{"username": username, "password": password, "remember": true}
	if token != "" {
		body["token"] = token
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/auth/login", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("reaching the controller: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	switch {
	case resp.StatusCode == 499:
		return TwoFactorError{}
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusBadRequest:
		return AuthError{Status: resp.StatusCode}
	case resp.StatusCode >= 400:
		return fmt.Errorf("login failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// get fetches a site-scoped classic-API path and decodes its data array.
//
// Only GET is exposed. The controller requires an X-CSRF-Token header before it
// will accept a write, and this client never reads one — so it cannot change
// the network even if a future caller asked it to.
func (c *Client) get(ctx context.Context, path string, out any) error {
	endpoint := fmt.Sprintf("%s/proxy/network/api/s/%s/%s", c.BaseURL, url.PathEscape(c.Site), path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return AuthError{Status: resp.StatusCode}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("fetching %s: HTTP %d", path, resp.StatusCode)
	}

	var envelope struct {
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if envelope.Meta.RC != "" && envelope.Meta.RC != "ok" {
		return fmt.Errorf("controller refused %s: %s", path, envelope.Meta.Msg)
	}
	if len(envelope.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// optional runs a fetch whose absence is not a failure. The rich firewall
// endpoints vanished from newer controllers, and a map that degrades is more
// useful than one that refuses to draw.
func (c *Client) optional(ctx context.Context, path string, out any) error {
	err := c.get(ctx, path, out)
	var authErr AuthError
	if errors.As(err, &authErr) {
		return err // a session problem is never "optional"
	}
	return nil
}
