package vssd

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCacheManagement verifies secure permission-gated read and write logic.
func TestCacheManagement(t *testing.T) {
	// Setup temporary custom home directory to isolate cache test
	tempHome, err := os.MkdirTemp("", "vane-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// Override HOME variable so GetCachePath points to our temporary home
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	iface := "test_eth0"
	token := "pve"
	entry := CacheEntry{
		IP:              "192.168.178.140",
		MAC:             "dc:39:6f:6d:9c:02",
		Ports:           []int{22, 8006},
		DiscoveryMethod: "active_fingerprint",
		LastSeen:        time.Now(),
	}

	// 1. Resolve from missing cache should fail gracefully
	ip, found := ResolveFromCache(iface, token)
	if found {
		t.Errorf("expected found=false for missing cache, got true (IP: %s)", ip)
	}

	// 2. Write to cache
	err = UpdateCache(iface, token, entry)
	if err != nil {
		t.Fatalf("failed to write to cache: %v", err)
	}

	// 3. Resolve from cache should now succeed
	resolvedIP, found := ResolveFromCache(iface, token)
	if !found {
		t.Fatalf("expected to resolve IP from cache, got miss")
	}
	if resolvedIP != entry.IP {
		t.Errorf("expected resolved IP %q, got %q", entry.IP, resolvedIP)
	}

	// 4. Verify POSIX owner-only permissions (0600) on the cache file
	cacheFile := filepath.Join(tempHome, ".config", "vane", "cache.json")
	info, err := os.Stat(cacheFile)
	if err != nil {
		t.Fatalf("failed to stat cache file: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("expected cache file permissions 0600 (-rw-------), got %04o", mode)
	}
}

// TestSubnetIPCalculation verifies calculation of IPs on a standard /24 subnet.
func TestSubnetIPCalculation(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.1.50/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}

	ips := getSubnetIPs(ipNet)
	if len(ips) != 254 {
		t.Errorf("expected 254 subnet IPs, got %d", len(ips))
	}

	if ips[0] != "192.168.1.1" {
		t.Errorf("expected first IP '192.168.1.1', got %q", ips[0])
	}

	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("expected last IP '192.168.1.254', got %q", ips[len(ips)-1])
	}
}

// TestARPCacheParsing ensures parser does not crash.
func TestARPCacheParsing(t *testing.T) {
	arpMap := parseARPCache("lo")
	// Should not crash and return a valid map (empty or filled depending on test host state)
	if arpMap == nil {
		t.Error("expected non-nil ARP map")
	}
}
