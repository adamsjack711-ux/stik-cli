package dissect

import (
	"net"
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/gopacket/gopacket/layers"
)

// fromARP reads the sender's MAC↔IP pairing — the ground truth of who is on
// the wire. Both ARP requests and replies carry a valid sender pairing.
func fromARP(arp *layers.ARP) (model.Observation, bool) {
	mac := normalizeMAC(net.HardwareAddr(arp.SourceHwAddress).String())
	if mac == "" {
		return model.Observation{}, false
	}
	obs := model.Observation{MAC: mac, Source: model.SourceARP}
	if ip := net.IP(arp.SourceProtAddress); len(ip) == 4 && !ip.IsUnspecified() {
		obs.IP = ip.String()
	}
	return obs, true
}

// normalizeMAC lowercases and validates a hardware address, returning "" for
// anything that isn't a 6-byte MAC (the broadcast address included).
func normalizeMAC(s string) string {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	if hw.String() == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return strings.ToLower(hw.String())
}
