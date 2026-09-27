package netstate

import (
	"net"
	"testing"
)

func TestGetInterfaceState(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("failed to read local network interfaces: %v", err)
	}

	if len(ifaces) == 0 {
		t.Skip("skipping test: no network interfaces found on host")
	}

	// Find first non-loopback interface for robust testing
	var target string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			target = iface.Name
			break
		}
	}
	if target == "" {
		t.Skip("skipping test: no non-loopback interface found")
	}

	state, err := GetInterfaceState(target)
	if err != nil {
		t.Fatalf("GetInterfaceState(%q) failed: %v", target, err)
	}

	if state.InterfaceName != target {
		t.Errorf("expected state interface %q, got %q", target, state.InterfaceName)
	}
}
