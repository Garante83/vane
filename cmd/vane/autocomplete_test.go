package main

import (
	"testing"
)

func TestSuggestVaneNotation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
	}{
		{
			name:     "Interface and modifier completed to suggestions",
			input:    "eno1|",
			contains: []string{"\"eno1|>...\"", "\"eno1|<...\"", "\"eno1|:\""},
		},
		{
			name:     "Modifier and dots complete to pve",
			input:    "eno1|>...pv",
			contains: []string{"\"eno1|>...pve\""},
		},
		{
			name:     "Modifier without dots completes to default three dots and pve",
			input:    "eno1|>pv",
			contains: []string{"\"eno1|>...pve\""},
		},
		{
			name:     "Modifier and dots complete to gw",
			input:    "eno1|>...g",
			contains: []string{"\"eno1|>...gw\""},
		},
		{
			name:     "Quoted input returns clean suggestions",
			input:    "\"eno1|>...pv",
			contains: []string{"eno1|>...pve"},
		},
		{
			name:     "Loopback modifier completes standard",
			input:    "lo|:1",
			contains: []string{"\"lo|:1\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suggestVaneNotation(tt.input)
			for _, expected := range tt.contains {
				found := false
				for _, g := range got {
					if g == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("suggestVaneNotation(%q) suggestions %v did not contain %q", tt.input, got, expected)
				}
			}
		})
	}
}

func TestFormatQuotes(t *testing.T) {
	input := []string{"\"eno1|>...pve\""}
	
	// Unquoted input
	gotUnquoted := formatQuotes(input, false)
	if gotUnquoted[0] != "\"eno1|>...pve\"" {
		t.Errorf("formatQuotes failed for unquoted: got %q", gotUnquoted[0])
	}

	// Quoted input
	gotQuoted := formatQuotes(input, true)
	if gotQuoted[0] != "eno1|>...pve" {
		t.Errorf("formatQuotes failed for quoted: got %q", gotQuoted[0])
	}
}
