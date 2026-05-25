package parser

import "testing"

func TestExtractToken(t *testing.T) {
	tests := []struct {
		input    string
		expected *Token
		found    bool
	}{
		{
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
			input: "eth0|<.100",
			expected: &Token{
				FullMatch: "eth0|<.100",
				Interface: "eth0",
				Direction: "<",
				Dots:      1,
				HostPart:  "100",
				Port:      "",
			},
			found: true,
		},
		{
			input: "invalid_input_here",
			expected: nil,
			found: false,
		},
	}

	for _, tc := range tests {
		res, ok := ExtractToken(tc.input)
		if ok != tc.found {
			t.Errorf("ExtractToken(%q) found=%v, expected=%v", tc.input, ok, tc.found)
			continue
		}
		if !ok {
			continue
		}
		if res.FullMatch != tc.expected.FullMatch ||
			res.Interface != tc.expected.Interface ||
			res.Direction != tc.expected.Direction ||
			res.Dots != tc.expected.Dots ||
			res.HostPart != tc.expected.HostPart ||
			res.Port != tc.expected.Port {
			t.Errorf("ExtractToken(%q) = %+v, expected %+v", tc.input, res, tc.expected)
		}
	}
}
