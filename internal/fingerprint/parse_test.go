package fingerprint

import "testing"

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		max  int
		want string
	}{
		{"strips CRLF", "SSH-2.0-OpenSSH_9.6p1\r\n", 200, "SSH-2.0-OpenSSH_9.6p1"},
		{"collapses whitespace", "220   mail\t\tESMTP  Postfix", 200, "220 mail ESMTP Postfix"},
		{"drops escape sequences", "hi\x1b[31mred\x1b[0m", 200, "hi[31mred[0m"},
		{"drops NUL", "a\x00b", 200, "ab"},
		{"truncates with ellipsis", "abcdefghij", 4, "abcd…"},
		{"empty stays empty", "\r\n\x00", 200, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeBanner(tc.raw, tc.max); got != tc.want {
				t.Errorf("sanitizeBanner(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseBanner(t *testing.T) {
	tests := []struct {
		name            string
		banner          string
		product, versio string
	}{
		{"openssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "OpenSSH", "9.6p1"},
		{"dropbear", "SSH-2.0-dropbear_2022.83", "dropbear", "2022.83"},
		{"postfix smtp", "220 mail.example.com ESMTP Postfix (Ubuntu)", "Postfix", ""},
		{"vsftpd", "220 (vsFTPd 3.0.5)", "vsftpd", "3.0.5"},
		{"proftpd with version", "220 ProFTPD 1.3.8 Server ready.", "ProFTPD", "1.3.8"},
		{"dovecot imap", "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "Dovecot", ""},
		{"generic slash version", "Redis/7.2.4 ready", "Redis", "7.2.4"},
		{"no version anywhere", "220 ready", "", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pv := parseBanner(tc.banner)
			if pv.Product != tc.product || pv.Version != tc.versio {
				t.Errorf("parseBanner(%q) = %q/%q, want %q/%q",
					tc.banner, pv.Product, pv.Version, tc.product, tc.versio)
			}
		})
	}
}

func TestParseServerHeader(t *testing.T) {
	tests := []struct {
		header          string
		product, versio string
	}{
		{"nginx/1.25.3", "nginx", "1.25.3"},
		{"Apache/2.4.58 (Ubuntu)", "Apache", "2.4.58"},
		{"Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"},
		{"nginx", "nginx", ""},
		{"gunicorn", "gunicorn", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			pv := parseServerHeader(tc.header)
			if pv.Product != tc.product || pv.Version != tc.versio {
				t.Errorf("parseServerHeader(%q) = %q/%q, want %q/%q",
					tc.header, pv.Product, pv.Version, tc.product, tc.versio)
			}
		})
	}
}

func TestParseHTMLTitle(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"plain", "<html><head><title>Router Admin</title></head>", "Router Admin"},
		{"attributes and case", `<TITLE lang="en">NAS  Login</TITLE>`, "NAS Login"},
		{"multiline", "<title>\n  Printer\n</title>", "Printer"},
		{"absent", "<html><body>hi</body></html>", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseHTMLTitle(tc.body); got != tc.want {
				t.Errorf("parseHTMLTitle(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
