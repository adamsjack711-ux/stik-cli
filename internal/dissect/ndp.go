package dissect

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// NDP is IPv6's answer to ARP, and stik listens to it for the same reason: it
// is the multicast conversation every device on the link takes part in, and it
// carries the MAC↔address pairing that makes a device identifiable.
//
// Three message types matter:
//
//   - Neighbor Advertisement (136) — "this address is mine, at this MAC". The
//     IPv6 equivalent of an ARP reply, and the strongest pairing available.
//   - Neighbor Solicitation (135) — "who has this address?". The sender's own
//     address and MAC come along for the ride.
//   - Router Advertisement (134) — a router announcing itself. Worth knowing
//     precisely because it says which box is routing the network.
//
// The link-layer address is read from the NDP option rather than the Ethernet
// header where one is present: a frame can be relayed, but the option is the
// sender's own statement about itself.

// fromNDP turns an ICMPv6 neighbor/router message into an observation.
func fromNDP(pkt gopacket.Packet, icmp *layers.ICMPv6) (model.Observation, bool) {
	srcMAC := ethSource(pkt)
	srcIP := ipv6Source(pkt)

	obs := model.Observation{MAC: srcMAC, Source: model.SourceNDP}

	switch icmp.TypeCode.Type() {
	case layers.ICMPv6TypeNeighborAdvertisement:
		adv := pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
		if adv == nil {
			return model.Observation{}, false
		}
		na := adv.(*layers.ICMPv6NeighborAdvertisement)
		// The target address is the one being claimed, which is the fact worth
		// keeping; the source address may be a link-local the device also holds.
		obs.IPv6 = ipString(na.TargetAddress)
		if mac := linkLayerAddr(na.Options); mac != "" {
			obs.MAC = mac
		}

	case layers.ICMPv6TypeNeighborSolicitation:
		sol := pkt.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
		if sol == nil {
			return model.Observation{}, false
		}
		ns := sol.(*layers.ICMPv6NeighborSolicitation)
		// A solicitation tells us about its *sender*, not the address it asks
		// after — recording the target would invent a device that may not exist.
		obs.IPv6 = srcIP
		if mac := linkLayerAddr(ns.Options); mac != "" {
			obs.MAC = mac
		}

	case layers.ICMPv6TypeRouterAdvertisement:
		ra := pkt.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
		if ra == nil {
			return model.Observation{}, false
		}
		r := ra.(*layers.ICMPv6RouterAdvertisement)
		obs.IPv6 = srcIP
		obs.Router = true
		if mac := linkLayerAddr(r.Options); mac != "" {
			obs.MAC = mac
		}

	default:
		return model.Observation{}, false
	}

	if obs.MAC == "" || obs.IPv6 == "" {
		return model.Observation{}, false
	}
	// An unspecified source (::) shows up during duplicate-address detection and
	// names nothing.
	if obs.IPv6 == "::" {
		return model.Observation{}, false
	}
	return obs, true
}

// linkLayerAddr reads the source/target link-layer address option, which is a
// device stating its own MAC rather than us inferring it from the frame.
func linkLayerAddr(opts layers.ICMPv6Options) string {
	for _, opt := range opts {
		switch opt.Type {
		case layers.ICMPv6OptSourceAddress, layers.ICMPv6OptTargetAddress:
			if len(opt.Data) == 6 {
				return normalizeMAC(net.HardwareAddr(opt.Data).String())
			}
		}
	}
	return ""
}

func ipv6Source(pkt gopacket.Packet) string {
	if ip := pkt.Layer(layers.LayerTypeIPv6); ip != nil {
		return ipString(ip.(*layers.IPv6).SrcIP)
	}
	return ""
}

func ipString(ip net.IP) string {
	if len(ip) == 0 || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}
