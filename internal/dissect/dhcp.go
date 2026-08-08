package dissect

import (
	"net"
	"strconv"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// fromDHCP reads a DHCP message. For a client message (DISCOVER/REQUEST/…) the
// prize is the Parameter Request List (option 55): the *set and order* of
// options a client asks for is a stable per-OS fingerprint that often reveals
// the operating system even when the MAC is randomized and no hostname is
// announced. Option 60 (vendor class, e.g. "android-dhcp-14") is an even more
// direct hint when present.
//
// For a server message (OFFER/ACK) the prize is different: it identifies a host
// on the segment that is handing out leases. A home network has exactly one —
// the router — so a second is the tell of a rogue or misconfigured DHCP server.
// Server messages echo the *client's* address in chaddr, so they must be keyed
// on the frame source (the server), never on ClientHWAddr.
func fromDHCP(payload []byte, srcMAC, srcIP string) (model.Observation, bool) {
	dhcp := &layers.DHCPv4{}
	if err := dhcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return model.Observation{}, false
	}

	msgType, serverID := dhcpMeta(dhcp)
	if msgType == layers.DHCPMsgTypeOffer || msgType == layers.DHCPMsgTypeAck {
		if srcMAC == "" {
			return model.Observation{}, false
		}
		ip := serverID // option 54 is the authoritative server address
		if ip == "" {
			ip = srcIP
		}
		return model.Observation{MAC: srcMAC, IP: ip, DHCPServer: true, Source: model.SourceDHCP}, true
	}

	mac := srcMAC
	if hw := net.HardwareAddr(dhcp.ClientHWAddr); len(hw) == 6 {
		if m := normalizeMAC(hw.String()); m != "" {
			mac = m // the client's own address, more reliable than the frame source
		}
	}
	if mac == "" {
		return model.Observation{}, false
	}

	obs := model.Observation{MAC: mac, Source: model.SourceDHCP}
	if ip := dhcp.ClientIP; ip != nil && !ip.IsUnspecified() {
		obs.IP = ip.String()
	}

	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptHostname:
			obs.Hostname = strings.ToLower(strings.TrimRight(string(opt.Data), "\x00 "))
		case layers.DHCPOptParamsRequest:
			obs.DHCPFingerprint = fingerprint(opt.Data)
		case layers.DHCPOptClassID:
			obs.DHCPVendorClass = strings.TrimRight(string(opt.Data), "\x00 ")
		}
	}
	return obs, true
}

// dhcpMeta pulls the message type (option 53) and server identifier (option 54)
// out of a decoded DHCP message. serverID is "" unless the packet carried a
// valid 4-byte option 54.
func dhcpMeta(dhcp *layers.DHCPv4) (msgType layers.DHCPMsgType, serverID string) {
	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptMessageType:
			if len(opt.Data) == 1 {
				msgType = layers.DHCPMsgType(opt.Data[0])
			}
		case layers.DHCPOptServerID:
			if len(opt.Data) == 4 {
				serverID = net.IP(opt.Data).String()
			}
		}
	}
	return msgType, serverID
}

// fingerprint renders the parameter-request list as its option codes in the
// exact order the client sent them — order is the discriminating part.
func fingerprint(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	codes := make([]string, len(data))
	for i, b := range data {
		codes[i] = strconv.Itoa(int(b))
	}
	return strings.Join(codes, ",")
}
