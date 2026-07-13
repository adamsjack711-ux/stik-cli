// Package identify turns raw device facts into a sentence a person can read.
// This is where stik earns its framing: nobody knows what a4:83:e7:2f:11:0c
// is, everybody knows what "Apple iPhone" is. Vendor + hostname + DHCP
// fingerprint go in; a Label and a plain-English Reason come out.
package identify

import (
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/identify/ouidata"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Input is the accumulated set of facts known about one device.
type Input struct {
	MAC             string
	Hostname        string
	DHCPFingerprint string
	DHCPVendorClass string
}

// Identify produces the human reading of a device.
func Identify(in Input) model.Identity {
	id := model.Identity{Private: IsPrivateMAC(in.MAC)}
	if !id.Private {
		if vendor, ok := ouidata.Lookup(in.MAC); ok {
			id.Vendor = vendor
		}
	}

	family := vendorFamily(id.Vendor)
	device := deviceType(in, family)
	id.Label, id.Reason = compose(id, family, device, in)
	return id
}

// IsPrivateMAC reports whether a MAC is locally administered — the tell of a
// randomized/private address. It is bit 0x02 of the first octet. When it's
// set, the OUI is invented, so vendor lookup would lie; we don't trust it.
func IsPrivateMAC(mac string) bool {
	clean := strings.NewReplacer(":", "", "-", "").Replace(mac)
	if len(clean) < 2 {
		return false
	}
	first, ok := hexByte(clean[0], clean[1])
	if !ok {
		return false
	}
	return first&0x02 != 0
}

func compose(id model.Identity, family, device string, in Input) (label, reason string) {
	os := osHint(in)

	switch {
	// A named device type wins, even over a randomized MAC — a phone that
	// announced "iPhone" over mDNS is an iPhone regardless of its address.
	case device != "" && family != "" && !strings.EqualFold(family, device):
		// Avoid stutter like "Apple Apple TV": if the product name already
		// leads with the brand, don't prepend it again.
		if strings.HasPrefix(strings.ToLower(device), strings.ToLower(family)) {
			label = device
		} else {
			label = family + " " + device
		}
	case device != "":
		label = device
	case family != "" && isIoTVendor(id.Vendor):
		label = "unknown device (" + family + " — likely IoT)"
	case family != "":
		label = family + " device"
	case id.Private:
		label = "device with a private address"
	default:
		label = "a device we don't recognize"
	}

	switch {
	case id.Private && in.Hostname != "":
		reason = "Its MAC address is randomized, but it announced the name \"" + in.Hostname + "\" on the network."
	case id.Private:
		reason = "It uses a randomized (private) MAC address, so its maker can't be identified from the hardware."
	case family != "" && os != "":
		reason = "Its network-card maker is " + family + ", and its DHCP fingerprint looks like " + os + "."
	case family != "" && isIoTVendor(id.Vendor):
		reason = family + " makes the Wi-Fi chips found in many smart-home and DIY gadgets."
	case family != "" && in.Hostname == "":
		reason = "Its network-card maker is " + family + "; it hasn't announced a name."
	case family != "":
		reason = "Its network-card maker is " + family + "."
	case os != "":
		reason = "Its hardware maker isn't in our database, but its DHCP fingerprint looks like " + os + "."
	default:
		reason = "Its hardware maker isn't in our database and it hasn't announced a name."
	}
	return label, reason
}

// vendorFamily maps a raw OUI vendor string to a short consumer brand.
func vendorFamily(vendor string) string {
	v := strings.ToLower(vendor)
	if v == "" {
		return ""
	}
	for _, f := range families {
		if strings.Contains(v, f.match) {
			return f.name
		}
	}
	// Not a brand we special-case: use the vendor's leading word, tidied up.
	if fields := strings.Fields(vendor); len(fields) > 0 {
		return fields[0]
	}
	return vendor
}

type family struct{ match, name string }

var families = []family{
	{"apple", "Apple"},
	{"amazon", "Amazon"},
	{"google", "Google"},
	{"samsung", "Samsung"},
	{"espressif", "Espressif"},
	{"raspberry", "Raspberry Pi"},
	{"roku", "Roku"},
	{"sonos", "Sonos"},
	{"ubiquiti", "Ubiquiti"},
	{"microsoft", "Microsoft"},
	{"intel", "Intel"},
	{"tp-link", "TP-Link"},
	{"tplink", "TP-Link"},
	{"xiaomi", "Xiaomi"},
	{"nest", "Google Nest"},
}

// isIoTVendor flags chip/module makers whose parts show up mostly in
// smart-home and DIY hardware rather than in a recognizable consumer product.
func isIoTVendor(vendor string) bool {
	v := strings.ToLower(vendor)
	for _, k := range []string{"espressif", "realtek", "tuya", "murata", "texas instruments", "microchip", "seeed", "shenzhen", "hangzhou"} {
		if strings.Contains(v, k) {
			return true
		}
	}
	return false
}

// deviceType infers a concrete product from the hostname and DHCP vendor class.
func deviceType(in Input, family string) string {
	host := strings.ToLower(in.Hostname)
	class := strings.ToLower(in.DHCPVendorClass)

	type rule struct{ needle, product string }
	hostRules := []rule{
		{"iphone", "iPhone"}, {"ipad", "iPad"}, {"macbook", "MacBook"},
		{"imac", "iMac"}, {"mac-mini", "Mac mini"}, {"macmini", "Mac mini"},
		{"apple-tv", "Apple TV"}, {"appletv", "Apple TV"}, {"airpods", "AirPods"},
		{"homepod", "HomePod"}, {"pixel", "Pixel"}, {"galaxy", "Galaxy phone"},
		{"kindle", "Kindle"}, {"echo", "Echo"}, {"alexa", "Echo"},
		{"firetv", "Fire TV"}, {"fire-tv", "Fire TV"}, {"chromecast", "Chromecast"},
		{"roku", "Roku"}, {"raspberrypi", "Raspberry Pi"}, {"raspberry", "Raspberry Pi"},
		{"sonos", "Sonos speaker"}, {"nest", "Nest device"},
	}
	for _, r := range hostRules {
		if strings.Contains(host, r.needle) {
			return r.product
		}
	}

	switch {
	case strings.HasPrefix(class, "android-dhcp"):
		return "Android device"
	case strings.HasPrefix(class, "msft"):
		return "Windows PC"
	}
	// "Watch" is only meaningful when we already know it's Apple.
	if strings.Contains(host, "watch") && family == "Apple" {
		return "Apple Watch"
	}
	return ""
}

// osHint gives a coarse OS guess, primarily from the DHCP vendor class (a
// direct, reliable signal) and secondarily from a few classic parameter-request
// fingerprints. It's a hint for the Reason line, not a hard claim.
func osHint(in Input) string {
	class := strings.ToLower(in.DHCPVendorClass)
	switch {
	case strings.HasPrefix(class, "android-dhcp"):
		return "Android"
	case strings.HasPrefix(class, "msft"):
		return "Windows"
	case strings.HasPrefix(class, "dhcpcd"), strings.HasPrefix(class, "udhcp"):
		return "Linux"
	}
	// Illustrative parameter-request-list signatures (option 55 ordering).
	switch in.DHCPFingerprint {
	case "1,121,3,6,15,119,252,95,44,46":
		return "macOS or iOS"
	case "1,3,6,15,26,28,51,58,59,43":
		return "Android"
	case "1,15,3,6,44,46,47,31,33,121,249,43":
		return "Windows"
	}
	return ""
}

func hexByte(hi, lo byte) (byte, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
