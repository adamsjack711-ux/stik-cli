package identify

import (
	"strings"
	"testing"

	"github.com/adamsjack711-ux/stik-cli/internal/identify/ouidata"
)

func TestEmbeddedTableLoaded(t *testing.T) {
	if n := ouidata.Count(); n < 30000 {
		t.Fatalf("embedded OUI table looks too small: %d entries", n)
	}
}

func TestVendorLookup(t *testing.T) {
	// a4:83:e7 is a registered Apple prefix.
	id := Identify(Input{MAC: "a4:83:e7:2f:11:0c"})
	if id.Vendor != "Apple" {
		t.Errorf("vendor = %q, want Apple", id.Vendor)
	}
	if id.Private {
		t.Error("a universally-administered Apple MAC should not be flagged private")
	}
}

func TestRandomizedMACDetection(t *testing.T) {
	// Bit 0x02 of the first octet = locally administered = randomized/private.
	// da:a1:19 has 0xda = 1101_1010, so the 0x02 bit is set.
	private := []string{
		"da:a1:19:11:22:33",
		"02:00:00:00:00:01",
		"7a:11:22:33:44:55", // 0x7a = 0111_1010
	}
	for _, m := range private {
		if !IsPrivateMAC(m) {
			t.Errorf("%s should be detected as a private/randomized MAC", m)
		}
	}
	public := []string{
		"a4:83:e7:2f:11:0c", // 0xa4 = 1010_0100, 0x02 bit clear
		"3c:07:54:00:00:01", // 0x3c = 0011_1100
	}
	for _, m := range public {
		if IsPrivateMAC(m) {
			t.Errorf("%s should NOT be detected as private", m)
		}
	}
}

func TestPrivateMACDoesNotReportVendor(t *testing.T) {
	// Even if a randomized address happened to collide with a real OUI prefix,
	// we must not confidently report that vendor.
	id := Identify(Input{MAC: "a6:83:e7:2f:11:0c"}) // a6 has the 0x02 bit set
	if !id.Private {
		t.Fatal("expected private MAC")
	}
	if id.Vendor != "" {
		t.Errorf("private MAC reported a vendor %q — should stay empty", id.Vendor)
	}
	if !strings.Contains(id.Label, "private") {
		t.Errorf("label = %q, want it to mention a private address", id.Label)
	}
}

func TestHostnameRescuesPrivateMAC(t *testing.T) {
	// A randomized MAC with an mDNS hostname is still identifiable by name.
	id := Identify(Input{MAC: "da:a1:19:11:22:33", Hostname: "dylans-iphone"})
	if id.Label != "iPhone" {
		t.Errorf("label = %q, want iPhone (from hostname despite private MAC)", id.Label)
	}
	if !strings.Contains(strings.ToLower(id.Reason), "randomized") {
		t.Errorf("reason = %q, want it to explain the randomized address", id.Reason)
	}
}

func TestVendorPlusHostnameSentence(t *testing.T) {
	id := Identify(Input{MAC: "a4:83:e7:2f:11:0c", Hostname: "dylans-iphone"})
	if id.Label != "Apple iPhone" {
		t.Errorf("label = %q, want 'Apple iPhone'", id.Label)
	}
}

func TestKnownVendorNoHostname(t *testing.T) {
	// fc:65:de is an Amazon prefix; with no hostname it's an "Amazon device".
	id := Identify(Input{MAC: "fc:65:de:00:00:01"})
	if !strings.HasPrefix(id.Label, "Amazon") {
		t.Errorf("label = %q, want it to start with Amazon", id.Label)
	}
}

func TestUnknownVendorDegradesGracefully(t *testing.T) {
	// 02:.. is locally administered (private) and unregistered.
	id := Identify(Input{MAC: "02:11:22:33:44:55"})
	if id.Label == "" {
		t.Error("label should never be empty")
	}
}

func TestAndroidVendorClass(t *testing.T) {
	id := Identify(Input{MAC: "da:a1:19:11:22:33", DHCPVendorClass: "android-dhcp-14"})
	if id.Label != "Android device" {
		t.Errorf("label = %q, want 'Android device'", id.Label)
	}
}

func TestEspressifFlaggedAsLikelyIoT(t *testing.T) {
	// 00:4b:12 is an Espressif prefix — a Wi-Fi chip maker, not a consumer brand.
	id := Identify(Input{MAC: "00:4b:12:00:00:01"})
	if !strings.Contains(id.Label, "IoT") {
		t.Errorf("label = %q, want it to flag likely IoT", id.Label)
	}
}

func TestNoBrandStutter(t *testing.T) {
	// "Apple TV" already starts with the brand; must not become "Apple Apple TV".
	id := Identify(Input{MAC: "3c:07:54:00:00:01", Hostname: "apple-tv"})
	if id.Label != "Apple TV" {
		t.Errorf("label = %q, want 'Apple TV' (no brand stutter)", id.Label)
	}
}
