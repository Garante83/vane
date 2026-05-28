package scan

import (
	"testing"
)

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
