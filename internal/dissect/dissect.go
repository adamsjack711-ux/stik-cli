// Package dissect turns raw link-layer frames into Observations. It parses
// only the three broadcast/multicast protocols stik listens to — ARP, mDNS,
// and DHCP — and nothing else on the wire.
//
// Everything here is pure: Frame([]byte) takes bytes and returns facts, with
// no capture, no cgo, no I/O. That is what lets the dissectors be tested
// against recorded packet fixtures.
package dissect

import (
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Frame parses one Ethernet frame and returns an observation if it carried
// something stik understands. ok is false for frames we don't care about or
// couldn't parse — dissecting is best-effort and never panics on junk.
func Frame(data []byte) (obs model.Observation, ok bool) {
	defer func() {
		// gopacket decoders are hardened, but a malformed packet from a hostile
		// network should degrade to "ignored", never crash the watcher.
		if r := recover(); r != nil {
			obs, ok = model.Observation{}, false
		}
	}()

	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	if arp := pkt.Layer(layers.LayerTypeARP); arp != nil {
		return fromARP(arp.(*layers.ARP))
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return model.Observation{}, false
	}
	udp := udpLayer.(*layers.UDP)
	srcMAC := ethSource(pkt)
	srcIP := ipSource(pkt)

	switch {
	case udp.DstPort == 5353 || udp.SrcPort == 5353:
		return fromMDNS(udp.Payload, srcMAC, srcIP)
	case udp.DstPort == 67 || udp.DstPort == 68 || udp.SrcPort == 67 || udp.SrcPort == 68:
		return fromDHCP(udp.Payload, srcMAC)
	}
	return model.Observation{}, false
}

func ethSource(pkt gopacket.Packet) string {
	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		return normalizeMAC(eth.(*layers.Ethernet).SrcMAC.String())
	}
	return ""
}

func ipSource(pkt gopacket.Packet) string {
	if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
		return ip.(*layers.IPv4).SrcIP.String()
	}
	return ""
}
