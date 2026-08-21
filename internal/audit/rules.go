// Package audit turns scan results into findings: a small, reviewable ruleset
// over the hosts and services the active pass observed, plus the writers that
// render them for a terminal or a browser.
//
// Every rule reports something the scan actually saw. Nothing here logs in,
// guesses at a CVE, or claims a service is vulnerable — a rule says "this is
// exposed" or "this is what the certificate says", and shows the evidence.
package audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Rule is one check against a single open service. Match returns the evidence
// that justifies the finding, or ok=false when the rule doesn't apply.
type Rule struct {
	ID       string
	Title    string
	Severity model.Severity
	Detail   string
	Fix      string
	Match    func(s model.Service) (evidence string, ok bool)
}

// exposedPorts are services that should not be reachable from a general-purpose
// network: remote control, file sharing, and datastores that historically ship
// with no authentication at all.
var exposedPorts = map[int]struct {
	id, name, why, fix string
	sev                model.Severity
}{
	23:    {"STIK-A001", "Telnet", "Telnet carries logins and commands in clear text; anyone on the path can read them.", "Disable telnet and use SSH instead.", model.SevHigh},
	3389:  {"STIK-A002", "RDP", "Remote Desktop is reachable. Exposed RDP is a routine entry point for credential stuffing and ransomware.", "Restrict RDP to a VPN or management range, and require network-level authentication.", model.SevHigh},
	5900:  {"STIK-A003", "VNC", "VNC is reachable. Many VNC servers default to weak or no authentication and no transport encryption.", "Tunnel VNC over SSH or a VPN rather than exposing it.", model.SevHigh},
	5901:  {"STIK-A003", "VNC", "VNC is reachable. Many VNC servers default to weak or no authentication and no transport encryption.", "Tunnel VNC over SSH or a VPN rather than exposing it.", model.SevHigh},
	445:   {"STIK-A004", "SMB", "SMB file sharing is reachable. It exposes shares and account names, and is the classic lateral-movement path.", "Limit SMB to the hosts that need it; never expose it beyond the local network.", model.SevHigh},
	6379:  {"STIK-A005", "Redis", "Redis is reachable. Unless it has been explicitly configured otherwise, Redis accepts commands from anyone who can connect.", "Bind Redis to localhost, or require a password and firewall the port.", model.SevHigh},
	27017: {"STIK-A006", "MongoDB", "MongoDB is reachable. Exposed instances have been mass-harvested for years.", "Bind MongoDB to localhost or a private range and enable authentication.", model.SevHigh},
	9200:  {"STIK-A007", "Elasticsearch", "Elasticsearch is reachable. Its HTTP API is fully administrative.", "Put Elasticsearch behind authentication and restrict the port.", model.SevHigh},
	11211: {"STIK-A008", "Memcached", "Memcached is reachable. It has no authentication and is a known reflection-amplification source.", "Bind memcached to localhost and firewall UDP/TCP 11211.", model.SevHigh},
	2375:  {"STIK-A009", "Docker API", "The unencrypted Docker daemon API is reachable. It is equivalent to root on the host.", "Never expose 2375. Use a local socket, or TLS client certs on 2376.", model.SevCritical},
}

// plaintextPorts carry credentials with no transport encryption.
var plaintextPorts = map[int]struct{ id, name, why, fix string }{
	21:  {"STIK-A020", "FTP", "FTP sends credentials and data in clear text.", "Move to SFTP or FTPS."},
	110: {"STIK-A021", "POP3", "POP3 without TLS sends mailbox credentials in clear text.", "Use POP3S (995) or require STARTTLS."},
	143: {"STIK-A022", "IMAP", "IMAP without TLS sends mailbox credentials in clear text.", "Use IMAPS (993) or require STARTTLS."},
	514: {"STIK-A023", "syslog", "Plain syslog is unauthenticated and unencrypted.", "Use syslog over TLS where the logs matter."},
}

// adminHints are page titles that say "this is a management interface".
var adminHints = []string{"admin", "login", "sign in", "router", "dashboard", "management", "console", "setup wizard"}

// osHints are the distro/OS strings daemons volunteer in banners.
var osHints = []string{"ubuntu", "debian", "centos", "red hat", "raspbian", "freebsd", "win32", "win64", "windows", "darwin", "alpine"}

// staleProducts is a deliberately small pinned table, not a CVE feed: the
// version below which a product is old enough to be worth a look. v1 says
// "this is behind", never "this is vulnerable" — that needs the --cve mode.
var staleProducts = map[string]string{
	"OpenSSH": "9.0",
	"nginx":   "1.24",
	"Apache":  "2.4.55",
	"vsftpd":  "3.0",
	"Dovecot": "2.3",
	"Exim":    "4.96",
	"ProFTPD": "1.3.8",
}

// Rules is the v1 ruleset, evaluated against every open service.
var Rules = buildRules()

func buildRules() []Rule {
	var rules []Rule

	for port, spec := range exposedPorts {
		port, spec := port, spec
		rules = append(rules, Rule{
			ID:       spec.id,
			Title:    spec.name + " reachable on the network",
			Severity: spec.sev,
			Detail:   spec.why,
			Fix:      spec.fix,
			Match: func(s model.Service) (string, bool) {
				if s.Port != port {
					return "", false
				}
				return describe(s), true
			},
		})
	}

	for port, spec := range plaintextPorts {
		port, spec := port, spec
		rules = append(rules, Rule{
			ID:       spec.id,
			Title:    spec.name + " without transport encryption",
			Severity: model.SevMedium,
			Detail:   spec.why,
			Fix:      spec.fix,
			Match: func(s model.Service) (string, bool) {
				if s.Port != port || s.TLS != nil {
					return "", false
				}
				return describe(s), true
			},
		})
	}

	rules = append(rules,
		Rule{
			ID:       "STIK-A030",
			Title:    "Admin interface served over plain HTTP",
			Severity: model.SevMedium,
			Detail:   "A management page is reachable over unencrypted HTTP, so its login travels in clear text across the network.",
			Fix:      "Serve the admin interface over HTTPS, and restrict it to a management range.",
			Match: func(s model.Service) (string, bool) {
				if s.TLS != nil || s.Banner == "" {
					return "", false
				}
				low := strings.ToLower(s.Banner)
				for _, hint := range adminHints {
					if strings.Contains(low, hint) {
						return "page title: " + s.Banner, true
					}
				}
				return "", false
			},
		},
		Rule{
			ID:       "STIK-A031",
			Title:    "Obsolete TLS version",
			Severity: model.SevMedium,
			Detail:   "The service negotiated a TLS version below 1.2. Those versions have known weaknesses and are rejected by current clients.",
			Fix:      "Enable TLS 1.2 and 1.3 and disable everything older.",
			Match: func(s model.Service) (string, bool) {
				if s.TLS == nil {
					return "", false
				}
				switch s.TLS.Version {
				case "TLS 1.0", "TLS 1.1":
					return "negotiated " + s.TLS.Version, true
				}
				return "", false
			},
		},
		Rule{
			ID:       "STIK-A032",
			Title:    "Expired TLS certificate",
			Severity: model.SevMedium,
			Detail:   "The certificate this service presents is past its expiry date, so clients cannot distinguish it from a substituted one.",
			Fix:      "Renew the certificate and automate the renewal.",
			Match: func(s model.Service) (string, bool) {
				if s.TLS == nil || !s.TLS.Expired {
					return "", false
				}
				return certEvidence(s.TLS) + ", expired " + s.TLS.NotAfter, true
			},
		},
		Rule{
			// Low, not medium: on a home or lab network a self-signed cert on a
			// NAS or printer is normal. It is worth knowing, not worth alarm.
			ID:       "STIK-A033",
			Title:    "Self-signed TLS certificate",
			Severity: model.SevLow,
			Detail:   "The certificate is its own issuer, so nothing vouches for this service's identity. Expected on appliances; a problem on anything clients are told to trust.",
			Fix:      "Issue the certificate from a CA your clients trust, even an internal one.",
			Match: func(s model.Service) (string, bool) {
				if s.TLS == nil || !s.TLS.SelfSigned || s.TLS.Expired {
					return "", false
				}
				return certEvidence(s.TLS), true
			},
		},
		Rule{
			ID:       "STIK-A040",
			Title:    "Service version is behind",
			Severity: model.SevLow,
			Detail:   "The version this service reports predates the pinned baseline stik-net carries. That is not a vulnerability claim — it is a prompt to check the changelog.",
			Fix:      "Update the package, or confirm your distro backports fixes to this version.",
			Match: func(s model.Service) (string, bool) {
				min, known := staleProducts[s.Product]
				if !known || s.Version == "" || !olderThan(s.Version, min) {
					return "", false
				}
				return fmt.Sprintf("%s %s (baseline %s)", s.Product, s.Version, min), true
			},
		},
		Rule{
			ID:       "STIK-A041",
			Title:    "Banner leaks host details",
			Severity: model.SevLow,
			Detail:   "The service announces its operating system or distribution to anyone who connects, which narrows an attacker's search for a matching exploit.",
			Fix:      "Trim the banner in the service's config (e.g. ServerTokens, DebianBanner).",
			Match: func(s model.Service) (string, bool) {
				if s.Banner == "" {
					return "", false
				}
				low := strings.ToLower(s.Banner)
				for _, hint := range osHints {
					if strings.Contains(low, hint) {
						return s.Banner, true
					}
				}
				return "", false
			},
		},
	)
	return rules
}

// describe is the standard evidence line for a port-based rule: whatever the
// fingerprint pass managed to learn, or the bare port when it learned nothing.
func describe(s model.Service) string {
	switch {
	case s.Product != "" && s.Version != "":
		return fmt.Sprintf("%d/tcp open — %s %s", s.Port, s.Product, s.Version)
	case s.Product != "":
		return fmt.Sprintf("%d/tcp open — %s", s.Port, s.Product)
	case s.Banner != "":
		return fmt.Sprintf("%d/tcp open — %s", s.Port, s.Banner)
	}
	return fmt.Sprintf("%d/tcp open", s.Port)
}

func certEvidence(t *model.TLSInfo) string {
	subject := t.Subject
	if subject == "" {
		subject = "(no common name)"
	}
	return "cert " + subject
}

// olderThan compares dotted numeric version prefixes: "9.6p1" < "10.0", and
// anything unparseable is treated as not-older so a weird string can't create a
// finding out of nothing.
func olderThan(have, min string) bool {
	h, m := versionParts(have), versionParts(min)
	for i := 0; i < len(h) && i < len(m); i++ {
		if h[i] != m[i] {
			return h[i] < m[i]
		}
	}
	return len(h) < len(m) && len(h) > 0
}

func versionParts(v string) []int {
	var parts []int
	for _, field := range strings.Split(v, ".") {
		digits := field
		for i, r := range field {
			if r < '0' || r > '9' {
				digits = field[:i]
				break
			}
		}
		if digits == "" {
			break
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			break
		}
		parts = append(parts, n)
	}
	return parts
}
