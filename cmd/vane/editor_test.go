package main

import (
	"encoding/json"
	"testing"
)

func TestValidateAndResolveIPInputDirect(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		iface     string
		expected  string
		expectErr bool
	}{
		{
			name:      "Valid IPv4",
			input:     "192.168.1.1",
			iface:     "lo",
			expected:  "192.168.1.1",
			expectErr: false,
		},
		{
			name:      "Valid IPv6",
			input:     "2001:db8::1",
			iface:     "lo",
			expected:  "2001:db8::1",
			expectErr: false,
		},
		{
			name:      "Empty input",
			input:     "",
			iface:     "lo",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid IP format",
			input:     "999.999.999.999",
			iface:     "lo",
			expected:  "",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := validateAndResolveIPInput(tc.input, tc.iface)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error for input %q, but got nil", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tc.input, err)
				}
				if res != tc.expected {
					t.Errorf("expected %q, got %q", tc.expected, res)
				}
			}
		})
	}
}

func TestTryAutoRepairJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name: "Heal missing closing brackets and braces",
			input: `{
				"eno1": {
					"pve": {
						"ip": "10.0.0.1"`,
			expectErr: false,
		},
		{
			name: "Heal trailing commas inside brackets",
			input: `{
				"eno1": {
					"pve": {
						"ip": "10.0.0.1",
					},
				},
			}`,
			expectErr: false,
		},
		{
			name: "Heal missing commas between consecutive entries",
			input: `{
				"eno1": {
					"pve": {
						"ip": "10.0.0.1"
					}
					"nas": {
						"ip": "10.0.0.2"
					}
				}
			}`,
			expectErr: false,
		},
		{
			name: "Heal multiple commas or trailing commas after brackets",
			input: `{
				"eno1": {
					"pve": {
						"ip": "10.0.0.1"
					},,,
				}
			}`,
			expectErr: false,
		},
		{
			name:      "Hopelessly broken JSON should still fail",
			input:     `{ "invalid-junk": [ ] invalid `,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repaired, err := tryAutoRepairJSON([]byte(tc.input))
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected repair error for input %q, but got nil", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tc.input, err)
				}
				var check map[string]interface{}
				if errUnmarshal := json.Unmarshal(repaired, &check); errUnmarshal != nil {
					t.Errorf("repaired result is still not valid JSON: %v (Repaired string: %q)", errUnmarshal, string(repaired))
				}
			}
		})
	}
}
