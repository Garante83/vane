package sniff

import "testing"

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{input: "hello\r\nworld", maxLen: 15, expected: "hello world"},
		{input: "this is a very long string", maxLen: 12, expected: "this is a..."},
	}

	for _, tc := range tests {
		res := truncateStr(tc.input, tc.maxLen)
		if res != tc.expected {
			t.Errorf("truncateStr(%q, %d) = %q, expected %q", tc.input, tc.maxLen, res, tc.expected)
		}
	}
}
