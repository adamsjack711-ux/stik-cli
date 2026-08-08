package dissect

import (
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

func TestARP(t *testing.T) {
	obs, ok := Frame(arpFrame("a4:83:e7:2f:11:0c", "192.168.1.42"))
	if !ok {
		t.Fatal("expected ARP frame to be dissected")
	}
	if obs.Source != model.SourceARP {
		t.Errorf("source = %q, want arp", obs.Source)
	}
	if obs.MAC != "a4:83:e7:2f:11:0c" {
		t.Errorf("MAC = %q", obs.MAC)
	}
	if obs.IP != "192.168.1.42" {
		t.Errorf("IP = %q", obs.IP)
	}
}

func TestARPUppercaseMACNormalized(t *testing.T) {
	obs, ok := Frame(arpFrame("A4:83:E7:2F:11:0C", "10.0.0.5"))
	if !ok || obs.MAC != "a4:83:e7:2f:11:0c" {
		t.Errorf("MAC not normalized to lowercase: %q ok=%v", obs.MAC, ok)
	}
}

func TestMDNSHostname(t *testing.T) {
	obs, ok := Frame(mdnsFrame("3c:07:54:aa:bb:cc", "192.168.1.20", "Dylans-iPhone", "192.168.1.20"))
	if !ok {
		t.Fatal("expected mDNS frame to be dissected")
	}
	if obs.Source != model.SourceMDNS {
		t.Errorf("source = %q, want mdns", obs.Source)
	}
	if obs.Hostname != "dylans-iphone" {
		t.Errorf("hostname = %q, want dylans-iphone", obs.Hostname)
	}
	if obs.MAC != "3c:07:54:aa:bb:cc" {
		t.Errorf("MAC = %q", obs.MAC)
	}
}

func TestMDNSServiceRecordIsNotAHostname(t *testing.T) {
	// A leading-underscore service name must not be mistaken for a device name.
	obs, ok := Frame(mdnsFrame("3c:07:54:aa:bb:cc", "192.168.1.20", "_airplay._tcp", "192.168.1.20"))
	if !ok {
		t.Fatal("expected dissection")
	}
	if obs.Hostname != "" {
		t.Errorf("hostname = %q, want empty (service record, not a device name)", obs.Hostname)
	}
}

func TestDHCPFingerprintAndVendorClass(t *testing.T) {
	params := []byte{1, 3, 6, 15, 26, 28, 51, 58, 59, 43}
	obs, ok := Frame(dhcpFrame("da:a1:19:00:00:01", "pixel-7", params, "android-dhcp-14"))
	if !ok {
		t.Fatal("expected DHCP frame to be dissected")
	}
	if obs.Source != model.SourceDHCP {
		t.Errorf("source = %q, want dhcp", obs.Source)
	}
	if obs.Hostname != "pixel-7" {
		t.Errorf("hostname = %q", obs.Hostname)
	}
	if obs.DHCPFingerprint != "1,3,6,15,26,28,51,58,59,43" {
		t.Errorf("fingerprint = %q", obs.DHCPFingerprint)
	}
	if obs.DHCPVendorClass != "android-dhcp-14" {
		t.Errorf("vendor class = %q", obs.DHCPVendorClass)
	}
	// The client hardware address is the device's real MAC.
	if obs.MAC != "da:a1:19:00:00:01" {
		t.Errorf("MAC = %q", obs.MAC)
	}
}

func TestDHCPFingerprintPreservesOrder(t *testing.T) {
	// Same option set, different order — must produce different fingerprints,
	// because order is the discriminating signal.
	a, _ := Frame(dhcpFrame("da:a1:19:00:00:02", "", []byte{1, 3, 6, 15}, ""))
	b, _ := Frame(dhcpFrame("da:a1:19:00:00:03", "", []byte{15, 6, 3, 1}, ""))
	if a.DHCPFingerprint == b.DHCPFingerprint {
		t.Errorf("reordered option lists produced identical fingerprints: %q", a.DHCPFingerprint)
	}
	if a.DHCPFingerprint != "1,3,6,15" {
		t.Errorf("fingerprint = %q, want 1,3,6,15", a.DHCPFingerprint)
	}
}

func TestDHCPClientMessageIsNotAServer(t *testing.T) {
	// A DISCOVER must never be mistaken for a server handing out leases.
	obs, ok := Frame(dhcpFrame("da:a1:19:00:00:04", "", []byte{1, 3, 6, 15}, ""))
	if !ok {
		t.Fatal("expected dissection")
	}
	if obs.DHCPServer {
		t.Error("client DISCOVER wrongly flagged as a DHCP server")
	}
}

func TestDHCPServerOfferDetected(t *testing.T) {
	// An OFFER identifies the server by frame source, not by chaddr (which holds
	// the client's MAC). The server identifier (option 54) is its IP.
	obs, ok := Frame(dhcpServerFrame("aa:bb:cc:00:00:01", "192.168.1.1", "da:a1:19:00:00:05"))
	if !ok {
		t.Fatal("expected DHCP offer to be dissected")
	}
	if !obs.DHCPServer {
		t.Error("DHCP offer not flagged as a server")
	}
	if obs.MAC != "aa:bb:cc:00:00:01" {
		t.Errorf("MAC = %q, want the server's frame-source MAC, not the client's chaddr", obs.MAC)
	}
	if obs.IP != "192.168.1.1" {
		t.Errorf("IP = %q, want the option-54 server identifier 192.168.1.1", obs.IP)
	}
}

func TestBroadcastMACIgnored(t *testing.T) {
	// A frame whose ARP sender is the broadcast address yields no device.
	if _, ok := Frame(arpFrame("ff:ff:ff:ff:ff:ff", "0.0.0.0")); ok {
		t.Error("broadcast sender should not produce an observation")
	}
}

func TestGarbageDoesNotPanicOrParse(t *testing.T) {
	for _, junk := range [][]byte{nil, {}, {0x00}, []byte("not a packet at all"), make([]byte, 14)} {
		if _, ok := Frame(junk); ok {
			t.Errorf("garbage %v was unexpectedly dissected", junk)
		}
	}
}
