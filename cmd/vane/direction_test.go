package main

import (
	"strings"
	"testing"
)

// TestGetDirectionName verifies bilingual direction descriptions incl. fallback
func TestGetDirectionName(t *testing.T) {
	cases := []struct {
		dir      string
		lang     string
		contains string
	}{
		{dir: ">", lang: "en", contains: "Outbound LAN"},
		{dir: ">", lang: "de", contains: "Lokales Subnetz"},
		{dir: "<", lang: "en", contains: "Global IPv6"},
		{dir: "<", lang: "de", contains: "Globale IPv6"},
		{dir: ":", lang: "en", contains: "Loopback"},
		{dir: ":", lang: "de", contains: "Lokaler Host"},
		{dir: "!", lang: "en", contains: "APIPA"},
		{dir: "!", lang: "de", contains: "Notfall"},
	}
	for _, tc := range cases {
		got := getDirectionName(tc.dir, tc.lang)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("getDirectionName(%q, %q) = %q, expected to contain %q", tc.dir, tc.lang, got, tc.contains)
		}
	}

	if got := getDirectionName("?", "en"); got != "Unbekannt" {
		t.Errorf("getDirectionName(unknown) = %q, expected fallback", got)
	}
}
