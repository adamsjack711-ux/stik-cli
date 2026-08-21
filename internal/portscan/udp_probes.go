package portscan

// UDP only answers if you speak to it. An empty datagram gets nothing back from
// a DNS resolver or an NTP server, so a scanner that sends one reports every
// live service as silent. These are the smallest well-formed requests each
// protocol will answer.
//
// Two lines this stays behind. Nothing here asks a service to *do* anything —
// every payload is a read or a presence check. And 67/68 get a generic probe
// rather than a real DHCPDISCOVER: requesting a lease would take an address off
// the network, which is a change, not an observation.

// udpProbe returns the payload for a port, or a single byte when we have no
// protocol to speak — enough to elicit an ICMP unreachable from a closed port.
func udpProbe(port int) []byte {
	if p, ok := udpProbes[port]; ok {
		return p
	}
	return []byte{0x00}
}

var udpProbes = map[int][]byte{
	53:   dnsQuery,
	123:  ntpClient,
	137:  netbiosNameQuery,
	161:  snmpGetSysDescr,
	623:  ipmiPresencePing,
	1900: ssdpDiscover,
	5353: mdnsServiceQuery,
	69:   tftpReadRequest,
}

// dnsQuery is a standard A query for "version.bind" in the CHAOS class — the
// conventional "are you a resolver, and will you say which one" question.
var dnsQuery = []byte{
	0x13, 0x37, // transaction id
	0x01, 0x00, // standard query, recursion desired
	0x00, 0x01, // one question
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
	0x04, 'b', 'i', 'n', 'd',
	0x00,       // end of name
	0x00, 0x10, // TXT
	0x00, 0x03, // CHAOS
}

// ntpClient is a mode-3 (client) packet: version 3, no authentication.
var ntpClient = append([]byte{0x1b}, make([]byte, 47)...)

// netbiosNameQuery is the node-status request ("*" wildcard name) that makes a
// Windows or Samba host list its NetBIOS names.
var netbiosNameQuery = []byte{
	0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, 'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 0x00,
	0x00, 0x21, // NBSTAT
	0x00, 0x01, // IN
}

// snmpGetSysDescr is a single SNMPv2c GET for sysDescr.0 using the default
// community "public". This is default-credential *detection*, not a spray: one
// request, and an answer is itself the finding — an agent that replies to
// "public" is readable by anyone who can reach the port.
var snmpGetSysDescr = []byte{
	0x30, 0x26,
	0x02, 0x01, 0x01, // version: v2c
	0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
	0xa0, 0x19,
	0x02, 0x04, 0x13, 0x37, 0x13, 0x37, // request id
	0x02, 0x01, 0x00, // error status
	0x02, 0x01, 0x00, // error index
	0x30, 0x0b,
	0x30, 0x09,
	0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // 1.3.6.1.2.1 (sysDescr prefix)
	0x05, 0x00,
}

// ipmiPresencePing is the ASF RMCP presence ping IPMI BMCs answer.
var ipmiPresencePing = []byte{
	0x06, 0x00, 0xff, 0x06, // RMCP header
	0x00, 0x00, 0x11, 0xbe, // ASF IANA
	0x80, 0x00, 0x00, 0x00, // presence ping
}

// ssdpDiscover is the UPnP M-SEARCH every media device and router answers.
var ssdpDiscover = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 1\r\n" +
	"ST: ssdp:all\r\n\r\n")

// mdnsServiceQuery asks what services a host advertises.
var mdnsServiceQuery = []byte{
	0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	0x07, '_', 'd', 'n', 's', '-', 's', 'd',
	0x04, '_', 'u', 'd', 'p',
	0x05, 'l', 'o', 'c', 'a', 'l',
	0x00,
	0x00, 0x0c, // PTR
	0x00, 0x01, // IN
}

// tftpReadRequest asks for a file that will not exist. The error reply is the
// signal; nothing is transferred.
var tftpReadRequest = append(append([]byte{0x00, 0x01}, []byte("stik-net-probe\x00")...), []byte("octet\x00")...)
