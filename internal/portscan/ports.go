package portscan

import (
	"errors"
	"syscall"
)

// DefaultTopPorts is a curated set of the most commonly-open TCP ports —
// enough to characterize a host quickly without a full 65k sweep. Ordered
// roughly by how often they matter on a real network, so `--top N` takes a
// meaningful slice. This is a pragmatic ~120-port list, not nmap's 1000.
var DefaultTopPorts = []int{
	80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
	111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152,
	2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049,
	88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432,
	1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899,
	9100, 119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103,
	6004, 1801, 5050, 19, 8031, 1041, 255, 27017, 6379, 9200, 11211, 23, 1521,
	161, 500, 5985, 5986, 7001,
}

// wellKnown maps ports to their conventional service name, for readable output.
// Not authoritative — the M3 fingerprint pass reads the real service off the
// wire; this is just a helpful label before then.
var wellKnown = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 19: "chargen", 21: "ftp", 22: "ssh",
	23: "telnet", 25: "smtp", 37: "time", 53: "dns", 79: "finger", 80: "http",
	81: "http-alt", 88: "kerberos", 106: "pop3pw", 110: "pop3", 111: "rpcbind",
	113: "ident", 119: "nntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 179: "bgp", 199: "smux", 389: "ldap", 427: "svrloc",
	443: "https", 444: "snpp", 445: "microsoft-ds", 465: "smtps", 500: "isakmp",
	513: "login", 514: "syslog", 515: "printer", 543: "klogin", 544: "kshell",
	548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 646: "ldp",
	873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1025: "msrpc",
	1433: "ms-sql", 1521: "oracle", 1720: "h323", 1723: "pptp", 1900: "upnp",
	2049: "nfs", 2121: "ccproxy-ftp", 3000: "ppp", 3128: "squid-http",
	3306: "mysql", 3389: "ms-wbt-server", 5000: "upnp", 5060: "sip",
	5432: "postgresql", 5631: "pcanywhere", 5666: "nrpe", 5800: "vnc-http",
	5900: "vnc", 5985: "wsman", 5986: "wsmans", 6000: "x11", 6379: "redis",
	7001: "weblogic", 8000: "http-alt", 8008: "http", 8009: "ajp13",
	8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
	9100: "jetdirect", 9200: "elasticsearch", 11211: "memcached",
	27017: "mongodb",
}

// ServiceName returns the conventional name for a port, or "" if unknown.
func ServiceName(port int) string { return wellKnown[port] }

// isRefused reports whether a dial error is a TCP refusal (RST) — a live host
// with the port closed, as opposed to a timeout or unreachable network.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
