package dissect

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// ndpFrame serializes a real ICMPv6 NDP frame, so the dissector is tested
// against the bytes libpcap would hand it.
func ndpFrame(t *testing.T, ethMAC, srcIP, dstIP string, icmpType uint8, body gopacket.SerializableLayer) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       mac(ethMAC),
		DstMAC:       mac("33:33:00:00:00:01"), // IPv6 multicast
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
	}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpType, 0)}
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("checksum layer: %v", err)
	}
	return serialize(eth, ip6, icmp, body)
}

func linkOpt(t *testing.T, optType layers.ICMPv6Opt, hw string) layers.ICMPv6Options {
	t.Helper()
	return layers.ICMPv6Options{{Type: optType, Data: mac(hw)}}
}

func TestNeighborAdvertisementPairsMACAndAddress(t *testing.T) {
	// The strongest pairing IPv6 offers: "this address is mine, at this MAC".
	frame := ndpFrame(t, "aa:bb:cc:dd:ee:01", "fe80::1", "ff02::1",
		layers.ICMPv6TypeNeighborAdvertisement,
		&layers.ICMPv6NeighborAdvertisement{
			TargetAddress: net.ParseIP("2001:db8::20"),
			Options:       linkOpt(t, layers.ICMPv6OptTargetAddress, "aa:bb:cc:dd:ee:01"),
		})

	obs, ok := Frame(frame)
	if !ok {
		t.Fatal("a neighbour advertisement should produce an observation")
	}
	if obs.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("mac = %q", obs.MAC)
	}
	// The claimed target address is the fact worth keeping — the source may be a
	// link-local the device also holds.
	if obs.IPv6 != "2001:db8::20" {
		t.Errorf("ipv6 = %q, want the advertised target address", obs.IPv6)
	}
	if obs.IP != "" {
		t.Errorf("ip = %q, want empty — this frame carried no IPv4", obs.IP)
	}
	if obs.Source != model.SourceNDP {
		t.Errorf("source = %q, want ndp", obs.Source)
	}
}

func TestNeighborSolicitationDescribesItsSenderNotItsTarget(t *testing.T) {
	// Recording the address being asked after would invent a device that may not
	// exist. Only the sender is a fact.
	frame := ndpFrame(t, "aa:bb:cc:dd:ee:02", "2001:db8::99", "ff02::1:ff00:20",
		layers.ICMPv6TypeNeighborSolicitation,
		&layers.ICMPv6NeighborSolicitation{
			TargetAddress: net.ParseIP("2001:db8::20"), // the address being sought
			Options:       linkOpt(t, layers.ICMPv6OptSourceAddress, "aa:bb:cc:dd:ee:02"),
		})

	obs, ok := Frame(frame)
	if !ok {
		t.Fatal("a neighbour solicitation should produce an observation")
	}
	if obs.IPv6 != "2001:db8::99" {
		t.Errorf("ipv6 = %q, want the sender's address, not the one it asked about", obs.IPv6)
	}
	if obs.IPv6 == "2001:db8::20" {
		t.Error("the solicited target must never be recorded as a device")
	}
}

func TestRouterAdvertisementMarksARouter(t *testing.T) {
	frame := ndpFrame(t, "aa:bb:cc:dd:ee:03", "fe80::1", "ff02::1",
		layers.ICMPv6TypeRouterAdvertisement,
		&layers.ICMPv6RouterAdvertisement{
			HopLimit: 64,
			Options:  linkOpt(t, layers.ICMPv6OptSourceAddress, "aa:bb:cc:dd:ee:03"),
		})

	obs, ok := Frame(frame)
	if !ok {
		t.Fatal("a router advertisement should produce an observation")
	}
	if !obs.Router {
		t.Error("a router advertisement should mark the sender as a router")
	}
	if obs.MAC != "aa:bb:cc:dd:ee:03" || obs.IPv6 != "fe80::1" {
		t.Errorf("obs = %+v", obs)
	}
}

func TestLinkLayerOptionBeatsTheEthernetHeader(t *testing.T) {
	// A frame can be relayed; the option is the device's own statement about
	// itself, so it wins.
	frame := ndpFrame(t, "00:00:00:00:00:ff", "fe80::5", "ff02::1",
		layers.ICMPv6TypeNeighborAdvertisement,
		&layers.ICMPv6NeighborAdvertisement{
			TargetAddress: net.ParseIP("2001:db8::5"),
			Options:       linkOpt(t, layers.ICMPv6OptTargetAddress, "aa:bb:cc:dd:ee:05"),
		})

	obs, ok := Frame(frame)
	if !ok {
		t.Fatal("want an observation")
	}
	if obs.MAC != "aa:bb:cc:dd:ee:05" {
		t.Errorf("mac = %q, want the address stated in the NDP option", obs.MAC)
	}
}

func TestDuplicateAddressDetectionNamesNothing(t *testing.T) {
	// DAD solicitations come from :: — a source that identifies no device.
	frame := ndpFrame(t, "aa:bb:cc:dd:ee:06", "::", "ff02::1:ff00:20",
		layers.ICMPv6TypeNeighborSolicitation,
		&layers.ICMPv6NeighborSolicitation{
			TargetAddress: net.ParseIP("2001:db8::20"),
			Options:       linkOpt(t, layers.ICMPv6OptSourceAddress, "aa:bb:cc:dd:ee:06"),
		})

	if obs, ok := Frame(frame); ok {
		t.Errorf("a DAD probe should be ignored, got %+v", obs)
	}
}

func TestOtherICMPv6IsIgnored(t *testing.T) {
	// Echo requests are a unicast conversation between other people.
	frame := ndpFrame(t, "aa:bb:cc:dd:ee:07", "2001:db8::7", "2001:db8::8",
		layers.ICMPv6TypeEchoRequest, &layers.ICMPv6Echo{Identifier: 1, SeqNumber: 1})

	if obs, ok := Frame(frame); ok {
		t.Errorf("echo should be ignored, got %+v", obs)
	}
}

func TestNDPWithoutALinkLayerOptionFallsBackToTheFrame(t *testing.T) {
	frame := ndpFrame(t, "aa:bb:cc:dd:ee:08", "fe80::8", "ff02::1",
		layers.ICMPv6TypeNeighborAdvertisement,
		&layers.ICMPv6NeighborAdvertisement{TargetAddress: net.ParseIP("2001:db8::8")})

	obs, ok := Frame(frame)
	if !ok {
		t.Fatal("want an observation")
	}
	if obs.MAC != "aa:bb:cc:dd:ee:08" {
		t.Errorf("mac = %q, want the Ethernet source as the fallback", obs.MAC)
	}
}
