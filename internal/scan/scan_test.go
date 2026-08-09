package scan

import (
	"net"
	"testing"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// dhcpOffer serializes a real DHCP OFFER from serverMAC/serverIP. chaddr holds
// the client's MAC, as a genuine OFFER does.
func dhcpOffer(serverMAC, serverIP, clientMAC string) []byte {
	sm, _ := net.ParseMAC(serverMAC)
	cm, _ := net.ParseMAC(clientMAC)
	eth := &layers.Ethernet{SrcMAC: sm, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(serverIP), DstIP: net.ParseIP("255.255.255.255")}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	udp.SetNetworkLayerForChecksum(ip)
	dhcp := &layers.DHCPv4{
		Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6,
		ClientHWAddr: cm,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)}),
			layers.NewDHCPOption(layers.DHCPOptServerID, net.ParseIP(serverIP).To4()),
		},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, dhcp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// arpFrame serializes an Ethernet+ARP announcement binding srcIP to srcMAC.
func arpFrame(srcMAC, srcIP string) []byte {
	src, _ := net.ParseMAC(srcMAC)
	eth := &layers.Ethernet{SrcMAC: src, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: src, SourceProtAddress: net.ParseIP(srcIP).To4(),
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: net.ParseIP("192.168.1.254").To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func fixedNow() time.Time { return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC) }

func TestUnknownDHCPServerFiresRogueNotNew(t *testing.T) {
	sc := New(registry.New(nil), fixedNow)
	var rogue, isNew int
	sc.OnDHCPServer = func(*model.Device) { rogue++ }
	sc.OnNew = func(*model.Device) { isNew++ }

	frame := dhcpOffer("aa:bb:cc:00:00:01", "192.168.1.1", "da:a1:19:00:00:09")
	sc.Handle(frame)

	if rogue != 1 {
		t.Errorf("OnDHCPServer fired %d times, want 1", rogue)
	}
	if isNew != 0 {
		t.Errorf("OnNew fired %d times, want 0 (rogue alert takes precedence)", isNew)
	}

	// A second identical observation must not re-alert — it's no longer a
	// transition.
	sc.Handle(frame)
	if rogue != 1 {
		t.Errorf("OnDHCPServer re-fired on repeat observation: %d", rogue)
	}
}

func TestKnownRouterServingDHCPDoesNotAlert(t *testing.T) {
	reg := registry.New([]*model.Device{{MAC: "aa:bb:cc:00:00:01", Name: "Router", Known: true}})
	sc := New(reg, fixedNow)
	fired := false
	sc.OnDHCPServer = func(*model.Device) { fired = true }

	sc.Handle(dhcpOffer("aa:bb:cc:00:00:01", "192.168.1.1", "da:a1:19:00:00:09"))
	if fired {
		t.Error("a trusted (Known) router serving DHCP should not raise a rogue alert")
	}
}

// clockFrom returns a now() reading a mutable time pointer, for time-sensitive
// conflict-window tests.
func clockFrom(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestConcurrentMACClaimFiresConflict(t *testing.T) {
	clk := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	sc := New(registry.New([]*model.Device{{MAC: "da:a1:19:00:00:01", Name: "router", Known: true}}), clockFrom(&clk))
	var conflict Conflict
	fired := 0
	sc.OnConflict = func(c Conflict) { conflict = c; fired++ }

	// The gateway IP is held by the router...
	sc.Handle(arpFrame("da:a1:19:00:00:01", "192.168.1.1"))
	// ...then, 30s later, an attacker claims the same IP. Concurrent -> conflict.
	clk = clk.Add(30 * time.Second)
	sc.Handle(arpFrame("66:66:66:66:66:66", "192.168.1.1"))

	if fired != 1 {
		t.Fatalf("OnConflict fired %d times, want 1", fired)
	}
	if conflict.IP != "192.168.1.1" || conflict.OldMAC != "da:a1:19:00:00:01" || conflict.NewMAC != "66:66:66:66:66:66" {
		t.Errorf("conflict = %+v", conflict)
	}
	if conflict.Old == nil || conflict.Old.Name != "router" {
		t.Errorf("expected previous owner to resolve to the known router, got %+v", conflict.Old)
	}

	// A repeat claim from the attacker within the cooldown must not re-alert.
	clk = clk.Add(10 * time.Second)
	sc.Handle(arpFrame("66:66:66:66:66:66", "192.168.1.1"))
	if fired != 1 {
		t.Errorf("conflict re-fired during cooldown: %d", fired)
	}
}

func TestStaleReassignmentIsNotAConflict(t *testing.T) {
	clk := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	sc := New(registry.New(nil), clockFrom(&clk))
	fired := 0
	sc.OnConflict = func(Conflict) { fired++ }

	sc.Handle(arpFrame("da:a1:19:00:00:02", "192.168.1.50"))
	// The old owner went quiet long ago; DHCP hands the address to someone else.
	clk = clk.Add(30 * time.Minute)
	sc.Handle(arpFrame("da:a1:19:00:00:03", "192.168.1.50"))

	if fired != 0 {
		t.Errorf("a reassignment after the old owner went quiet must not alert (fired %d)", fired)
	}
}
