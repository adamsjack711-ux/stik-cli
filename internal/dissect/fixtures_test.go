package dissect

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// These helpers serialize real, on-the-wire frames so the dissectors are tested
// against genuine packet bytes — the same thing libpcap would hand them — not
// against mocks of gopacket's own structs.

func serialize(lys ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, lys...); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func mac(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return hw
}

// arpFrame builds an Ethernet+ARP request announcing sender MAC/IP.
func arpFrame(srcMAC, srcIP string) []byte {
	src := mac(srcMAC)
	eth := &layers.Ethernet{
		SrcMAC:       src,
		DstMAC:       mac("ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   src,
		SourceProtAddress: net.ParseIP(srcIP).To4(),
		DstHwAddress:      mac("00:00:00:00:00:00"),
		DstProtAddress:    net.ParseIP("192.168.1.1").To4(),
	}
	return serialize(eth, arp)
}

// mdnsFrame builds an Ethernet+IPv4+UDP(5353)+DNS response announcing an A
// record for host.local at the given IP.
func mdnsFrame(srcMAC, srcIP, host, aRecordIP string) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       mac(srcMAC),
		DstMAC:       mac("01:00:5e:00:00:fb"),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP("224.0.0.251"),
	}
	udp := &layers.UDP{SrcPort: 5353, DstPort: 5353}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		QR:      true,
		OpCode:  layers.DNSOpCodeQuery,
		ANCount: 1,
		Answers: []layers.DNSResourceRecord{{
			Name:  []byte(host + ".local"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   120,
			IP:    net.ParseIP(aRecordIP).To4(),
		}},
	}
	return serialize(eth, ip, udp, dns)
}

// dhcpFrame builds an Ethernet+IPv4+UDP(68→67)+DHCP Discover carrying a
// hostname, a parameter-request list, and a vendor class.
func dhcpFrame(srcMAC, hostname string, paramList []byte, vendorClass string) []byte {
	client := mac(srcMAC)
	eth := &layers.Ethernet{
		SrcMAC:       client,
		DstMAC:       mac("ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("0.0.0.0"),
		DstIP:    net.ParseIP("255.255.255.255"),
	}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	udp.SetNetworkLayerForChecksum(ip)

	opts := layers.DHCPOptions{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
	}
	if hostname != "" {
		opts = append(opts, layers.NewDHCPOption(layers.DHCPOptHostname, []byte(hostname)))
	}
	if len(paramList) > 0 {
		opts = append(opts, layers.NewDHCPOption(layers.DHCPOptParamsRequest, paramList))
	}
	if vendorClass != "" {
		opts = append(opts, layers.NewDHCPOption(layers.DHCPOptClassID, []byte(vendorClass)))
	}
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x12345678,
		ClientHWAddr: client,
		Options:      opts,
	}
	return serialize(eth, ip, udp, dhcp)
}

// dhcpOfferFrame builds an Ethernet+IPv4+UDP(67→68)+DHCP Offer from a server.
// Note the chaddr echoes the *client's* MAC, exactly as a real OFFER does — the
// dissector must key the observation on the server (frame source), not chaddr.
func dhcpServerFrame(serverMAC, serverIP, clientMAC string) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       mac(serverMAC),
		DstMAC:       mac("ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(serverIP),
		DstIP:    net.ParseIP("255.255.255.255"),
	}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	udp.SetNetworkLayerForChecksum(ip)

	opts := layers.DHCPOptions{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)}),
		layers.NewDHCPOption(layers.DHCPOptServerID, net.ParseIP(serverIP).To4()),
	}
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x12345678,
		YourClientIP: net.ParseIP("192.168.1.50").To4(),
		ClientHWAddr: mac(clientMAC),
		Options:      opts,
	}
	return serialize(eth, ip, udp, dhcp)
}
