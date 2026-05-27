package uip

import (
	"net"
	"strings"
	"testing"

	"vane/pkg/netstate"
)

// TestExtractToken verifies the parser's regex correctness under all format conditions.
func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *Token
		found    bool
	}{
		{
			name:  "Valid Outbound LAN with Gateway and Port",
			input: "eno1|>...gw:80",
			expected: &Token{
				FullMatch: "eno1|>...gw:80",
				Interface: "eno1",
				Direction: ">",
				Dots:      3,
				HostPart:  "gw",
				Port:      "80",
			},
			found: true,
		},
		{
			name:  "Valid External WAN with Hex Suffix",
			input: "eth0|<.3e8e",
			expected: &Token{
				FullMatch: "eth0|<.3e8e",
				Interface: "eth0",
				Direction: "<",
				Dots:      1,
				HostPart:  "3e8e",
				Port:      "",
			},
			found: true,
		},
		{
			name:  "Valid Loopback",
			input: "lo|:...1",
			expected: &Token{
				FullMatch: "lo|:...1",
				Interface: "lo",
				Direction: ":",
				Dots:      3,
				HostPart:  "1",
				Port:      "",
			},
			found: true,
		},
		{
			name:  "APIPA Warning Suffix",
			input: "wlan0|!...34",
			expected: &Token{
				FullMatch: "wlan0|!...34",
				Interface: "wlan0",
				Direction: "!",
				Dots:      3,
				HostPart:  "34",
				Port:      "",
			},
			found: true,
		},
		{
			name:  "Whitespace padding compatibility",
			input: "eno1   |>...53",
			expected: &Token{
				FullMatch: "eno1   |>...53",
				Interface: "eno1",
				Direction: ">",
				Dots:      3,
				HostPart:  "53",
				Port:      "",
			},
			found: true,
		},
		{
			name:  "Outbound LAN with port and greedy regex check",
			input: "eno1|>...33:2222",
			expected: &Token{
				FullMatch: "eno1|>...33:2222",
				Interface: "eno1",
				Direction: ">",
				Dots:      3,
				HostPart:  "33",
				Port:      "2222",
			},
			found: true,
		},
		{
			name:  "Outbound LAN with MAC suffix and port greedy check",
			input: "eno1|>...3e:8e:2222",
			expected: &Token{
				FullMatch: "eno1|>...3e:8e:2222",
				Interface: "eno1",
				Direction: ">",
				Dots:      3,
				HostPart:  "3e:8e",
				Port:      "2222",
			},
			found: true,
		},
		{
			name:     "Invalid syntax",
			input:    "invalid_token_pattern",
			expected: nil,
			found:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, ok := ExtractToken(tc.input)
			if ok != tc.found {
				t.Errorf("found=%v, expected=%v", ok, tc.found)
				return
			}
			if !ok {
				return
			}
			if res.FullMatch != tc.expected.FullMatch ||
				res.Interface != tc.expected.Interface ||
				res.Direction != tc.expected.Direction ||
				res.Dots != tc.expected.Dots ||
				res.HostPart != tc.expected.HostPart ||
				res.Port != tc.expected.Port {
				t.Errorf("got %+v, expected %+v", res, tc.expected)
			}
		})
	}
}

// TestResolveTokenIP_Success verifies successful resolutions under active states.
func TestResolveTokenIP_Success(t *testing.T) {
	tests := []struct {
		name       string
		token      Token
		state      netstate.State
		expectedIP string
	}{
		{
			name: "IPv4 segment replacement (3 dots)",
			token: Token{
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
			name: "IPv4 multi-segment replacement (2 dots)",
			token: Token{
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
			token: Token{
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
			token: Token{
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
			token: Token{
				Direction: ":",
				HostPart:  "1",
			},
			state:      netstate.State{},
			expectedIP: "::1",
		},
		{
			name: "APIPA active mapping",
			token: Token{
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
			name: "APIPA fallback generator",
			token: Token{
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
			name: "EUI-64 MAC address matching",
			token: Token{
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
			res, err := ResolveTokenIP(&tt.token, &tt.state)
			if err != nil {
				t.Fatalf("unexpected resolution error: %v", err)
			}
			if res != tt.expectedIP {
				t.Errorf("expected %q, got %q", tt.expectedIP, res)
			}
		})
	}
}

// TestResolveTokenIP_Errors checks that the library returns clean Go errors on failures.
func TestResolveTokenIP_Errors(t *testing.T) {
	tests := []struct {
		name          string
		token         Token
		state         netstate.State
		expectedError string
	}{
		{
			name: "Missing IPv4 address on interface",
			token: Token{
				Direction: ">",
				Dots:      3,
				HostPart:  "33",
			},
			state: netstate.State{
				InterfaceName: "eth0",
				IPv4Local:     nil,
			},
			expectedError: "Keine valide IPv4-Adresse",
		},
		{
			name: "APIPA lease fail warning block",
			token: Token{
				Direction: ">",
				Dots:      3,
				HostPart:  "33",
			},
			state: netstate.State{
				InterfaceName: "eth0",
				IPv4Local:     net.ParseIP("169.254.1.2"),
				IsAPIPA:       true,
			},
			expectedError: "APIPA erkannt auf",
		},
		{
			name: "Missing global IPv6 address on WAN modifier",
			token: Token{
				Direction: "<",
				Dots:      3,
				HostPart:  "33",
			},
			state: netstate.State{
				InterfaceName: "eth0",
				IPv6Global:    nil,
			},
			expectedError: "Keine globale IPv6-Adresse",
		},
		{
			name: "MAC suffix mismatches hardware address and ARP scan failure",
			token: Token{
				Direction: ">",
				Dots:      3,
				HostPart:  "99aa",
			},
			state: netstate.State{
				InterfaceName: "eth0",
				IPv4Local:     net.ParseIP("192.168.178.50"),
				HardwareAddr:  net.HardwareAddr{0x00, 0x15, 0x5d, 0x01, 0x3e, 0x8e},
			},
			expectedError: "MAC-Suffix '99aa' stimmt nicht mit Interface eth0 überein",
		},
		{
			name: "Invalid modifier token",
			token: Token{
				Direction: "?",
				Dots:      3,
				HostPart:  "33",
			},
			state:         netstate.State{},
			expectedError: "Unbekannter Richtungs-Modifikator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveTokenIP(&tt.token, &tt.state)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedError)
			}
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("expected error %q to contain %q", err.Error(), tt.expectedError)
			}
		})
	}
}

// TestUtilityFunctions covers static networking helper algorithms.
func TestUtilityFunctions(t *testing.T) {
	// 1. EUI-64 MAC Generation
	mac, err := net.ParseMAC("00:15:5d:01:02:03")
	if err != nil {
		t.Fatalf("failed to parse MAC: %v", err)
	}
	eui := ComputeEUI64(mac)
	if eui != "0215:5dff:fe01:0203" {
		t.Errorf("ComputeEUI64 failed: expected 0215:5dff:fe01:0203, got %q", eui)
	}

	// 2. Prefix /64 extraction
	ip := net.ParseIP("2001:db8:a::1")
	prefix := GetPrefix64(ip, "fallback:")
	if prefix != "2001:db8:a::" {
		t.Errorf("GetPrefix64 failed: expected 2001:db8:a::, got %q", prefix)
	}

	// 3. Dot replacements
	ipV4 := net.ParseIP("192.168.1.50")
	res := ResolveIPv4Dots(ipV4, 3, "99")
	if res != "192.168.1.99" {
		t.Errorf("ResolveIPv4Dots failed: expected 192.168.1.99, got %q", res)
	}
}
