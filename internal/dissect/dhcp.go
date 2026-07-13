package dissect

import (
	"net"
	"strconv"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// fromDHCP reads a DHCP message. The prize here is the client's Parameter
// Request List (option 55): the *set and order* of options a client asks for
// is a stable per-OS fingerprint that often reveals the operating system even
// when the MAC is randomized and no hostname is announced. Option 60 (vendor
// class, e.g. "android-dhcp-14") is an even more direct hint when present.
func fromDHCP(payload []byte, srcMAC string) (model.Observation, bool) {
	dhcp := &layers.DHCPv4{}
	if err := dhcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return model.Observation{}, false
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
