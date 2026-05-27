package main

import (
	"net"
	"testing"
	"vane/pkg/uip"
)

func TestComputeEUI64(t *testing.T) {
	mac, err := net.ParseMAC("00:15:5d:01:02:03")
	if err != nil {
		t.Fatalf("failed to parse MAC: %v", err)
	}

	eui := uip.ComputeEUI64(mac)
	if eui != "0215:5dff:fe01:0203" {
		t.Errorf("expected 0215:5dff:fe01:0203, got %q", eui)
	}
}

func TestGetPrefix64(t *testing.T) {
	ip := net.ParseIP("2001:db8:a::1")
	prefix := uip.GetPrefix64(ip, "fallback:")
	if prefix != "2001:db8:a::" {
		t.Errorf("expected 2001:db8:a::, got %q", prefix)
	}
}

func TestResolveIPv4Dots(t *testing.T) {
	ip := net.ParseIP("192.168.1.50")
	res := uip.ResolveIPv4Dots(ip, 3, "99")
	if res != "192.168.1.99" {
		t.Errorf("expected 192.168.1.99, got %q", res)
	}
}

func TestExtractPortFromFlags(t *testing.T) {
	args := []string{"-h", "-p", "22", "ssh"}
	port := extractPortFromFlags(args)
	if port != "22" {
		t.Errorf("expected 22, got %q", port)
	}
}

func TestGetSystemLanguage(t *testing.T) {
	lang := getSystemLanguage()
	if lang != "de" && lang != "en" {
		t.Errorf("expected de or en, got %q", lang)
	}
}
