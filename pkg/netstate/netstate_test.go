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

	// Dynamically query the first active interface name on the system
	target := ifaces[0].Name
	state, err := GetInterfaceState(target)
	if err != nil {
		t.Fatalf("GetInterfaceState(%q) failed: %v", target, err)
	}

	if state.InterfaceName != target {
		t.Errorf("expected state interface %q, got %q", target, state.InterfaceName)
	}
}
