package main

import (
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
