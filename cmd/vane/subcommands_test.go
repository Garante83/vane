package main

import (
	"testing"
	"vane/pkg/vssd"
)

func TestGetSpelledOutName(t *testing.T) {
	tests := []struct {
		token    string
		expected string
	}{
		{"pve", "Proxmox VE"},
		{"nas", "Nextcloud/NAS"},
		{"hass", "Home Assistant"},
		{"pi", "Raspberry Pi"},
		{"other", "other"},
	}

	for _, tc := range tests {
		actual := getSpelledOutName(tc.token)
		if actual != tc.expected {
			t.Errorf("getSpelledOutName(%q) = %q; expected %q", tc.token, actual, tc.expected)
		}
	}
}

func TestGetSpelledOutNameCustom(t *testing.T) {
	entryWithCustomName := vssd.CacheEntry{
		Name: "My Custom Service",
	}
	actual := getSpelledOutNameCustom("nas", entryWithCustomName)
	if actual != "My Custom Service" {
		t.Errorf("expected 'My Custom Service', got %q", actual)
	}

	entryWithoutCustomName := vssd.CacheEntry{
		Name: "",
	}
	actualFallback := getSpelledOutNameCustom("nas", entryWithoutCustomName)
	if actualFallback != "Nextcloud/NAS" {
		t.Errorf("expected fallback 'Nextcloud/NAS', got %q", actualFallback)
	}
}
