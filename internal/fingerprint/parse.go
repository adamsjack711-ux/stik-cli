package fingerprint

import (
	"regexp"
	"strings"
)

// sanitizeBanner strips control characters and collapses whitespace so a banner
// is safe to print in a terminal and a report, then truncates it.
func sanitizeBanner(raw string, max int) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r == '\t' || r == ' ':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// drop other control bytes (CR/LF/NUL/escape) entirely
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(strings.Join(strings.Fields(b.String()), " "))
	if len(out) > max {
		out = strings.TrimSpace(out[:max]) + "…"
	}
	return out
}

// productVersion is (product, version) parsed from a banner line.
type productVersion struct {
	Product string
	Version string
}

var (
	// "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3" → OpenSSH / 9.6p1
	reSSH = regexp.MustCompile(`^SSH-\d[\d.]*-([A-Za-z][\w.+-]*?)[_/ ]v?([\d][\w.]*)`)
	// Generic "Product/1.2.3" or "Product 1.2.3" anywhere in a banner.
	reSlashVer = regexp.MustCompile(`([A-Za-z][A-Za-z0-9.+-]*?)[/ ]v?(\d+(?:\.\d+){1,3}\w*)`)
)

// parseBanner extracts a best-effort product/version from a raw service banner
// (SSH, SMTP, FTP, POP3/IMAP greetings, and the like).
func parseBanner(banner string) productVersion {
	s := strings.TrimSpace(banner)
	if s == "" {
		return productVersion{}
	}
	if m := reSSH.FindStringSubmatch(s); m != nil {
		return productVersion{Product: m[1], Version: m[2]}
	}
	// SMTP/FTP/POP: known daemons announce themselves by name in the greeting.
	// Matched case-insensitively — real banners vary ("vsFTPd", "ProFTPD") — but
	// reported under the canonical spelling.
	lower := strings.ToLower(s)
	for _, name := range []string{"Postfix", "Exim", "Sendmail", "vsftpd", "ProFTPD", "Dovecot", "Pure-FTPd", "OpenSMTPD"} {
		i := strings.Index(lower, strings.ToLower(name))
		if i < 0 {
			continue
		}
		pv := productVersion{Product: name}
		if m := reSlashVer.FindStringSubmatch(s[i:]); m != nil && strings.EqualFold(m[1], name) {
			pv.Version = m[2]
		}
		return pv
	}
	if m := reSlashVer.FindStringSubmatch(s); m != nil {
		return productVersion{Product: m[1], Version: m[2]}
	}
	return productVersion{}
}

// parseServerHeader turns an HTTP Server header value into product/version,
// e.g. "nginx/1.25.3" → nginx / 1.25.3, "Apache/2.4.58 (Ubuntu)" → Apache/2.4.58.
func parseServerHeader(server string) productVersion {
	s := strings.TrimSpace(server)
	if s == "" {
		return productVersion{}
	}
	if m := reSlashVer.FindStringSubmatch(s); m != nil {
		return productVersion{Product: m[1], Version: m[2]}
	}
	// Server header with a bare product name and no version.
	if f := strings.Fields(s); len(f) > 0 {
		return productVersion{Product: strings.TrimRight(f[0], ",;")}
	}
	return productVersion{}
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// parseHTMLTitle pulls the <title> text from an HTML body, sanitized.
func parseHTMLTitle(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return sanitizeBanner(m[1], 80)
}
