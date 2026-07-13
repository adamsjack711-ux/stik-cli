package capture

import "testing"

func TestChoosePrefersPhysicalOverVirtual(t *testing.T) {
	got, ok := chooseInterface([]Candidate{
		{Name: "lo0", Up: true, Loopback: true, IPv4s: []string{"127.0.0.1"}},
		{Name: "utun3", Up: true, IPv4s: []string{"10.8.0.2"}},
		{Name: "en0", Up: true, IPv4s: []string{"192.168.1.10"}},
	})
	if !ok || got != "en0" {
		t.Errorf("chose %q (ok=%v), want en0", got, ok)
	}
}

func TestChooseSkipsLoopbackAndDownAndAddressless(t *testing.T) {
	got, ok := chooseInterface([]Candidate{
		{Name: "lo0", Up: true, Loopback: true, IPv4s: []string{"127.0.0.1"}},
		{Name: "en0", Up: false, IPv4s: []string{"192.168.1.10"}}, // down
		{Name: "en1", Up: true, IPv4s: nil},                       // no address
		{Name: "eth0", Up: true, IPv4s: []string{"10.0.0.5"}},
	})
	if !ok || got != "eth0" {
		t.Errorf("chose %q (ok=%v), want eth0", got, ok)
	}
}

func TestChooseFallsBackToVirtualWhenOnlyOption(t *testing.T) {
	got, ok := chooseInterface([]Candidate{
		{Name: "utun0", Up: true, IPv4s: []string{"10.8.0.2"}},
	})
	if !ok || got != "utun0" {
		t.Errorf("chose %q (ok=%v), want utun0 as last resort", got, ok)
	}
}

func TestChooseNothingUsable(t *testing.T) {
	if _, ok := chooseInterface([]Candidate{
		{Name: "lo0", Up: true, Loopback: true, IPv4s: []string{"127.0.0.1"}},
		{Name: "en0", Up: false},
	}); ok {
		t.Error("expected no usable interface")
	}
}
