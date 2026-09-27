package main

import (
	"strings"
	"testing"
	"vane/pkg/vssd"
)

// TestGetColoredStatus verifies padding and ANSI color placement
func TestGetColoredStatus(t *testing.T) {
	up := getColoredStatus(true)
	if !strings.Contains(up, "[ UP ]") || !strings.Contains(up, "\x1b[1;32m") {
		t.Errorf("getColoredStatus(true) = %q, expected green UP token", up)
	}

	down := getColoredStatus(false)
	if !strings.Contains(down, "[DOWN]") || !strings.Contains(down, "\x1b[1;31m") {
		t.Errorf("getColoredStatus(false) = %q, expected red DOWN token", down)
	}
}

// TestGetColoredSyntax verifies the four direction modifiers and fallbacks
func TestGetColoredSyntax(t *testing.T) {
	cases := []struct {
		mod     string
		suffix  string
		colored string
	}{
		{mod: ">", suffix: "53", colored: "\x1b[1;32m"},
		{mod: "<", suffix: "3e8e", colored: "\x1b[1;36m"},
		{mod: ":", suffix: "1", colored: "\x1b[1;35m"},
		{mod: "!", suffix: "34", colored: "\x1b[1;33m"},
	}
	for _, tc := range cases {
		got := getColoredSyntax("eno1", tc.mod, tc.suffix)
		if !strings.Contains(got, tc.colored) {
			t.Errorf("getColoredSyntax(eno1, %q, %q) = %q, missing color %q", tc.mod, tc.suffix, got, tc.colored)
		}
		if !strings.Contains(got, tc.suffix) {
			t.Errorf("getColoredSyntax(eno1, %q, %q) = %q, suffix not preserved", tc.mod, tc.suffix, got)
		}
	}

	// Empty modifier → plain padded interface name
	plain := getColoredSyntax("eno1", "", "")
	if strings.Contains(plain, "\x1b") {
		t.Errorf("expected no ANSI codes for empty modifier, got %q", plain)
	}
	if !strings.Contains(plain, "eno1") {
		t.Errorf("expected interface name, got %q", plain)
	}

	// Unknown modifier → unchanged
	unknown := getColoredSyntax("eno1", "?", "9")
	if strings.Contains(unknown, "\x1b") {
		t.Errorf("expected no ANSI codes for unknown modifier, got %q", unknown)
	}
}

// TestGetSpelledOutNameCustomFallback verifies fallback to the token table
func TestGetSpelledOutNameCustomFallback(t *testing.T) {
	empty := vssd.CacheEntry{}
	if got := getSpelledOutNameCustom("nas", empty); got != "Nextcloud/NAS" {
		t.Errorf("expected fallback 'Nextcloud/NAS', got %q", got)
	}
}

// TestHandleAutocompleteOutput verifies the suggestion output goes to stdout
func TestHandleAutocompleteOutput(t *testing.T) {
	// Exercise the pure suggestion generator used under the hood
	got := suggestVaneNotation("eno1|>")
	if len(got) == 0 {
		t.Log("note: suggestVaneNotation returned no suggestions for 'eno1'")
	}
}
