package dissect

import (
	"strings"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// fromMDNS reads a multicast-DNS message. Apple and many IoT devices announce
// themselves constantly (e.g. Dylans-iPhone.local), which is free, high-quality
// identity. Even a query with no useful records still proves the sender's MAC
// is on the wire, so we return an observation as long as we know the source.
func fromMDNS(payload []byte, srcMAC, srcIP string) (model.Observation, bool) {
	if srcMAC == "" {
		return model.Observation{}, false
	}
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return model.Observation{}, false
	}

	obs := model.Observation{MAC: srcMAC, IP: srcIP, Source: model.SourceMDNS}
	for _, section := range [][]layers.DNSResourceRecord{dns.Answers, dns.Additionals, dns.Authorities} {
		for _, rr := range section {
			if obs.Hostname == "" {
				if h := hostnameFromRecord(rr); h != "" {
					obs.Hostname = h
				}
			}
			if obs.IP == "" && (rr.Type == layers.DNSTypeA || rr.Type == layers.DNSTypeAAAA) && rr.IP != nil {
				obs.IP = rr.IP.String()
			}
		}
	}
	return obs, true
}

// hostnameFromRecord pulls a device hostname out of an A/AAAA record whose
// name is a plain <host>.local. Service records (leading "_") and reverse-DNS
// (.arpa) names are not device names, so they're skipped.
func hostnameFromRecord(rr layers.DNSResourceRecord) string {
	if rr.Type != layers.DNSTypeA && rr.Type != layers.DNSTypeAAAA {
		return ""
	}
	name := strings.ToLower(strings.TrimSuffix(string(rr.Name), "."))
	if !strings.HasSuffix(name, ".local") {
		return ""
	}
	label := strings.TrimSuffix(name, ".local")
	if label == "" || strings.HasPrefix(label, "_") || strings.Contains(label, ".arpa") || strings.Contains(label, ".") {
		return ""
	}
	return label
}
