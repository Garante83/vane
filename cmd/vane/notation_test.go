package main

import (
	"net"
	"testing"
	"vane/pkg/netstate"
	"vane/pkg/uip"
)

// TestResolveTokenIP_Success runs a comprehensive suite of table-driven tests checking
// that every Vane operator resolves exactly to its designated IP target given specific state profiles.
func TestResolveTokenIP_Success(t *testing.T) {
	tests := []struct {
		name       string
		token      uip.Token
		state      netstate.State
		expectedIP string
	}{
		{
			name: "IPv4 local segment replacement (3 dots)",
			token: uip.Token{
				Direction: ">",
				Dots:      3,
				HostPart:  "33",
			},
			state: netstate.State{
				IPv4Local: net.ParseIP("192.168.178.50"),
			},
			expectedIP: "192.168.178.33",
		},
		{
			name: "IPv4 local multi-segment replacement (2 dots)",
			token: uip.Token{
				Direction: ">",
				Dots:      2,
				HostPart:  "100.33",
			},
			state: netstate.State{
				IPv4Local: net.ParseIP("192.168.178.50"),
			},
			expectedIP: "192.168.100.33",
		},
		{
			name: "IPv6 ULA segment replacement",
			token: uip.Token{
				Direction: ">",
				Dots:      3,
				HostPart:  "33",
			},
			state: netstate.State{
				IPv6ULA: net.ParseIP("fd00::1ac0:4dff:feda:3e8e"),
			},
			expectedIP: "fd00::1ac0:4dff:feda:33",
		},
		{
			name: "Loopback IPv4 mapping",
			token: uip.Token{
				Direction: ":",
				Dots:      3,
				HostPart:  "254",
			},
			state: netstate.State{
				IPv4Local: net.ParseIP("127.0.0.1"),
			},
			expectedIP: "127.0.0.254",
		},
		{
			name: "Loopback IPv6 mapping",
			token: uip.Token{
				Direction: ":",
				HostPart:  "1",
			},
			state:      netstate.State{},
			expectedIP: "::1",
		},
		{
			name: "APIPA Emergency mapping (APIPA active)",
			token: uip.Token{
				Direction: "!",
				Dots:      3,
				HostPart:  "34",
			},
			state: netstate.State{
				IPv4Local: net.ParseIP("169.254.0.10"),
				IsAPIPA:   true,
			},
			expectedIP: "169.254.0.34",
		},
		{
			name: "APIPA Emergency mapping (APIPA not active)",
			token: uip.Token{
				Direction: "!",
				Dots:      3,
				HostPart:  "34",
			},
			state: netstate.State{
				IPv4Local: net.ParseIP("192.168.178.50"),
				IsAPIPA:   false,
			},
			expectedIP: "169.254.0.34",
		},
		{
			name: "Local Hardware Address EUI-64 Matching under LAN",
			token: uip.Token{
				Direction: ">",
				Dots:      3,
				HostPart:  "3e8e",
			},
			state: netstate.State{
				IPv4Local:    net.ParseIP("192.168.178.50"),
				HardwareAddr: net.HardwareAddr{0x00, 0x15, 0x5d, 0x01, 0x3e, 0x8e},
			},
			expectedIP: "192.168.178.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := uip.ResolveTokenIP(&tt.token, &tt.state)
			if err != nil {
				t.Fatalf("unexpected error resolving token: %v", err)
			}
			if res != tt.expectedIP {
				t.Errorf("expected %q, got %q", tt.expectedIP, res)
			}
		})
	}
}
