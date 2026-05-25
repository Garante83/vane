package scan

import (
	"net"
	"testing"
)

func TestGetSubnetIPs(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.1.1/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}

	ips := getSubnetIPs(ipNet)
	// A standard /24 CIDR subnet has 254 available host addresses (omitting .0 and .255)
	if len(ips) != 254 {
		t.Errorf("expected 254 IPs, got %d", len(ips))
	}

	if ips[0].String() != "192.168.1.1" {
		t.Errorf("expected first host IP to be 192.168.1.1, got %s", ips[0].String())
	}
	if ips[len(ips)-1].String() != "192.168.1.254" {
		t.Errorf("expected last host IP to be 192.168.1.254, got %s", ips[len(ips)-1].String())
	}
}

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		ports    []string
		expected string
	}{
		{ports: []string{}, expected: "──"},
		{ports: []string{"80"}, expected: "[80]"},
		{ports: []string{"80", "443"}, expected: "[80,443]"},
		{ports: []string{"22", "80", "443"}, expected: "[22,80,...]"},
	}

	for _, tc := range tests {
		res := formatPorts(tc.ports)
		if res != tc.expected {
			t.Errorf("formatPorts(%v) = %q, expected %q", tc.ports, res, tc.expected)
		}
	}
}

func TestResolveVendor(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{mac: "B8:27:EB:12:34:56", expected: "Raspberry Pi"},
		{mac: "08:00:27:12:34:56", expected: "VirtualBox"},
		{mac: "11:22:33:44:55:66", expected: ""},
	}

	for _, tc := range tests {
		res := resolveVendor(tc.mac)
		if res != tc.expected {
			t.Errorf("resolveVendor(%q) = %q, expected %q", tc.mac, res, tc.expected)
		}
	}
}
