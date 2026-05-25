package trace

import (
	"testing"
	"time"
)

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{input: "hello", maxLen: 10, expected: "hello"},
		{input: "hello world!", maxLen: 8, expected: "hello..."},
	}

	for _, tc := range tests {
		res := truncateStr(tc.input, tc.maxLen)
		if res != tc.expected {
			t.Errorf("truncateStr(%q, %d) = %q, expected %q", tc.input, tc.maxLen, res, tc.expected)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	res := formatDuration(5 * time.Millisecond)
	if res != "5.0ms" {
		t.Errorf("expected 5.0ms, got %s", res)
	}
}

func TestRenderSparkline(t *testing.T) {
	tests := []struct {
		history  []time.Duration
		expected string
	}{
		{history: []time.Duration{}, expected: ""},
		{history: []time.Duration{0}, expected: "✖"},
		{history: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}, expected: " █"},
	}

	for _, tc := range tests {
		res := renderSparkline(tc.history)
		if res != tc.expected {
			t.Errorf("renderSparkline(%v) = %q, expected %q", tc.history, res, tc.expected)
		}
	}
}
