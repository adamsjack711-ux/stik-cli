// Package cve enriches fingerprinted services with known vulnerabilities from
// the NVD. It is the one part of stik-net that talks to the internet, and it
// only runs when asked.
//
// Everything else in this tool works on a network it does not trust: the OUI
// table is embedded rather than fetched, the reports pull in no remote assets,
// and the passive watcher transmits nothing at all. Sending the software
// inventory of someone's network to a third party is a different kind of act,
// so it lives behind an explicit flag, says what it is about to do, and caches
// what it learns so a re-audit does not repeat the disclosure.
package cve

import (
	"fmt"
	"strings"
)

// Product maps a fingerprinted product name to the NVD's vendor and product
// terms. The table is small and hand-checked on purpose: a wrong guess here
// does not produce no answer, it produces confident wrong answers about
// somebody else's software.
type Product struct {
	Vendor  string
	Product string
}

var products = map[string]Product{
	"openssh":       {"openbsd", "openssh"},
	"nginx":         {"f5", "nginx"},
	"apache":        {"apache", "http_server"},
	"httpd":         {"apache", "http_server"},
	"lighttpd":      {"lighttpd", "lighttpd"},
	"microsoft-iis": {"microsoft", "internet_information_services"},
	"postfix":       {"postfix", "postfix"},
	"exim":          {"exim", "exim"},
	"dovecot":       {"dovecot", "dovecot"},
	"vsftpd":        {"beasts", "vsftpd"},
	"proftpd":       {"proftpd", "proftpd"},
	"pure-ftpd":     {"pureftpd", "pure-ftpd"},
	"samba":         {"samba", "samba"},
	"openssl":       {"openssl", "openssl"},
	"mysql":         {"oracle", "mysql"},
	"mariadb":       {"mariadb", "mariadb"},
	"postgresql":    {"postgresql", "postgresql"},
	"redis":         {"redis", "redis"},
	"mongodb":       {"mongodb", "mongodb"},
	"memcached":     {"memcached", "memcached"},
	"elasticsearch": {"elastic", "elasticsearch"},
	"dropbear":      {"dropbear_ssh_project", "dropbear_ssh"},
	"dnsmasq":       {"thekelleys", "dnsmasq"},
	"bind":          {"isc", "bind"},
	"squid":         {"squid-cache", "squid"},
	"jetty":         {"eclipse", "jetty"},
	"tomcat":        {"apache", "tomcat"},
	"node.js":       {"nodejs", "node.js"},
	"openvpn":       {"openvpn", "openvpn"},
}

// Lookup maps a product name to its CPE terms, reporting whether the product is
// one we are prepared to be right about.
func Lookup(product string) (Product, bool) {
	p, ok := products[strings.ToLower(strings.TrimSpace(product))]
	return p, ok
}

// CPE builds the 2.3 name NVD matches against. Version is normalized to its
// dotted numeric prefix: NVD does not know what "9.6p1" is, but it knows 9.6.
func CPE(p Product, version string) string {
	v := numericVersion(version)
	if v == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", p.Vendor, p.Product, v)
}

// numericVersion keeps the leading dotted-numeric part of a version string, so
// "9.6p1 Ubuntu-3" becomes "9.6" — the part a CPE match can use.
func numericVersion(v string) string {
	v = strings.TrimSpace(v)
	var out strings.Builder
	digitSeen := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			out.WriteByte(c)
			digitSeen = true
		case c == '.' && digitSeen:
			// Stop at a second dot-run that is not followed by a digit.
			if i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
				out.WriteByte(c)
				continue
			}
			return trimDot(out.String())
		default:
			return trimDot(out.String())
		}
	}
	return trimDot(out.String())
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }
