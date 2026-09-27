package sniff

import (
	"testing"
	"vane/pkg/util"
)

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
		res := util.TruncateStr(tc.input, tc.maxLen)
		if res != tc.expected {
			t.Errorf("util.TruncateStr(%q, %d) = %q, expected %q", tc.input, tc.maxLen, res, tc.expected)
		}
	}
}
