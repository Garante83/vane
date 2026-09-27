package main

import (
	"strings"
	"testing"
)

// TestSuggestVaneNotation verifies notation continuation suggestions
func TestSuggestVaneNotation(t *testing.T) {
	// Bare modifier: should offer >, <, : variants
	got := suggestVaneNotation("eno1|")
	if len(got) < 3 {
		t.Fatalf("expected at least 3 suggestions for 'eno1|', got %v", got)
	}
	for _, s := range got {
		if !strings.Contains(s, "eno1|") {
			t.Errorf("suggestion %q missing iface part", s)
		}
	}

	// Quoted input strips quotes (formatQuotes intentionally trims them)
	for _, s := range suggestVaneNotation("\"eno1|>") {
		if !strings.Contains(s, "eno1|>") {
			t.Errorf("quoted suggestion %q missing notation part", s)
		}
	}

	// Non-notation input → no suggestions
	if got := suggestVaneNotation("ls -la"); len(got) != 0 {
		t.Errorf("expected no suggestions for plain words, got %v", got)
	}
}

// TestSuggestVaneNotationSemanticCompletion verifies semantic token
// completion (e.g. "pv" -> "pve") inside a Vane notation token
func TestSuggestVaneNotationSemanticCompletion(t *testing.T) {
	got := suggestVaneNotation("eno1|>...pv")
	found := false
	for _, s := range got {
		if strings.Contains(s, "pve") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'pve' completion suggestion for 'eno1|>...pv', got %v", got)
	}
}
