// Package capture is stik's one link to the network. It is strictly passive:
// it opens a read-only pcap handle in non-promiscuous mode and installs a BPF
// filter that admits only the broadcast/multicast protocols stik understands
// (ARP, mDNS, DHCP). It never transmits — no ARP scan, no probes, nothing.
package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gopacket/gopacket/pcap"
)

// The only traffic stik is allowed to see: ARP, NDP (IPv6 neighbour and router
// discovery), mDNS (5353) and DHCP (67/68). Every one of these is broadcast or
// multicast — traffic any host on the LAN legitimately receives. Unicast
// between other devices is invisible to us on a switched network, by design and
// by physics.
//
// NDP is filtered down to the three message types stik reads rather than all of
// ICMPv6: echo requests and error messages are unicast conversations between
// other people, and there is no reason to have them in the buffer.
const bpfFilter = "arp or (udp port 5353) or (udp port 67) or (udp port 68) or " +
	"(icmp6 and (ip6[40] = 134 or ip6[40] = 135 or ip6[40] = 136))"

const snapLen = 1600 // these packets are small; full frames fit comfortably

// Capture is an open, passive capture session.
type Capture struct {
	handle *pcap.Handle
	iface  string
}

// Interface returns the interface being listened on.
func (c *Capture) Interface() string { return c.iface }

// PermissionError signals that packet capture was denied — almost always a
// matter of privileges rather than a real fault. The CLI turns this into a
// friendly explanation instead of a raw stack trace.
type PermissionError struct {
	Iface string
	Err   error
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("no permission to capture on %s: %v", e.Iface, e.Err)
}
func (e *PermissionError) Unwrap() error { return e.Err }

// NoInterfaceError signals that no usable network interface was found.
type NoInterfaceError struct{}

func (NoInterfaceError) Error() string { return "no active network interface found" }

// DetectInterface returns the interface stik will listen on, honoring the
// STIK_IFACE override, otherwise auto-selecting. It never asks the user.
func DetectInterface() (string, error) {
	if forced := os.Getenv("STIK_IFACE"); forced != "" {
		return forced, nil
	}
	candidates, err := gatherCandidates()
	if err != nil {
		return "", err
	}
	if name, ok := chooseInterface(candidates); ok {
		return name, nil
	}
	return "", NoInterfaceError{}
}

// Open starts a passive capture. If iface is empty it is auto-detected.
func Open(iface string) (*Capture, error) {
	if iface == "" {
		detected, err := DetectInterface()
		if err != nil {
			return nil, err
		}
		iface = detected
	}

	// Non-promiscuous: broadcast/multicast reaches us without promiscuous mode,
	// and staying out of it is both lower-impact and closer to the tool's ethos.
	handle, err := pcap.OpenLive(iface, snapLen, false, pcap.BlockForever)
	if err != nil {
		if isPermissionError(err) {
			return nil, &PermissionError{Iface: iface, Err: err}
		}
		return nil, fmt.Errorf("opening %s: %w", iface, err)
	}
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("setting capture filter: %w", err)
	}
	return &Capture{handle: handle, iface: iface}, nil
}

// Run delivers raw frames to fn until ctx is cancelled or the handle closes.
// fn must not retain the byte slice beyond the call.
func (c *Capture) Run(ctx context.Context, fn func(data []byte)) error {
	// Closing the handle from another goroutine unblocks ReadPacketData,
	// letting a BlockForever read honor context cancellation.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.handle.Close()
		case <-done:
		}
	}()

	for {
		data, _, err := c.handle.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return nil // cancellation, not a failure
			}
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			return nil // handle closed / EOF
		}
		fn(data)
	}
}

// Close releases the capture handle.
func (c *Capture) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}

func isPermissionError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"permission", "operation not permitted", "bpf", "not permitted", "access is denied"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return errors.Is(err, os.ErrPermission)
}
