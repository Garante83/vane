package vssd

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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

// TestARPCacheParsing ensures parser does not crash.
func TestARPCacheParsing(t *testing.T) {
	arpMap := parseARPCache("lo")
	// Should not crash and return a valid map (empty or filled depending on test host state)
	if arpMap == nil {
		t.Error("expected non-nil ARP map")
	}
}

// TestPassiveARPDiscovery verifies the passive ARP signature scanning does not crash and runs safely.
func TestPassiveARPDiscovery(t *testing.T) {
	results, err := RunPassiveARPDiscovery("lo")
	if err != nil {
		t.Fatalf("RunPassiveARPDiscovery failed: %v", err)
	}
	if results == nil {
		t.Error("expected non-nil results map")
	}
}

// TestIsAmbiguousPort verifies that ambiguous and unique ports are correctly segregated.
func TestIsAmbiguousPort(t *testing.T) {
	ambiguous := []int{22, 80, 443, 3000, 8080, 9000}
	for _, port := range ambiguous {
		if !isAmbiguousPort(port) {
			t.Errorf("expected port %d to be ambiguous", port)
		}
	}

	unambiguous := []int{8006, 8123, 32400, 5432, 6379}
	for _, port := range unambiguous {
		if isAmbiguousPort(port) {
			t.Errorf("expected port %d to be non-ambiguous", port)
		}
	}
}

// TestFindSignature verifies standard token extraction.
func TestFindSignature(t *testing.T) {
	sig, found := FindSignature("pve")
	if !found {
		t.Error("expected signature 'pve' to be found")
	}
	if sig.DisplayName != "Proxmox VE" {
		t.Errorf("expected DisplayName 'Proxmox VE', got %q", sig.DisplayName)
	}

	_, found = FindSignature("invalid_token_xyz")
	if found {
		t.Error("expected signature 'invalid_token_xyz' to not be found")
	}
}

// TestPeekServiceFingerprint dynamically starts an HTTP mock server and checks HTML payload fingerprinting.
func TestPeekServiceFingerprint(t *testing.T) {
	var currentBody string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body := currentBody
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	testCases := []struct {
		body     string
		expected string
	}{
		{"<html><body>Welcome to Proxmox VE</body></html>", "pve"},
		{"<title>Open WebUI</title>", "owu"},
		{"Welcome to nextcloud storage", "ncd"},
		{"Welcome to paperless-ngx document manager", "ppl"},
		{"Home Assistant dashboard", "hass"},
		{"Elasticsearch server: you know, for search", "els"},
		{"Unknown page", ""},
	}

	for _, tc := range testCases {
		mu.Lock()
		currentBody = tc.body
		mu.Unlock()

		token := peekServiceFingerprint(host, port)
		if token != tc.expected {
			t.Errorf("for body %q, expected token %q, got %q", tc.body, tc.expected, token)
		}
	}
}

// TestEnsureCacheOwnershipSanity verifies that EnsureCacheOwnership runs safely and returns early under non-root
func TestEnsureCacheOwnershipSanity(t *testing.T) {
	tempFile, err := os.CreateTemp("", "vane-cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	// Should run safely and do nothing since we are not root/sudo
	EnsureCacheOwnership(tempFile.Name())
}

// TestRunTargetedDiscoverySanity runs RunTargetedDiscovery on the loopback interface as a safety and coverage check
func TestRunTargetedDiscoverySanity(t *testing.T) {
	// Setup temporary custom home directory to isolate cache test
	tempHome, err := os.MkdirTemp("", "vane-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	_, _ = RunTargetedDiscovery("lo")
}

// TestRunSingleTargetDiscoverySanity runs RunSingleTargetDiscovery on loopback for a single target
func TestRunSingleTargetDiscoverySanity(t *testing.T) {
	// Setup temporary custom home directory to isolate cache test
	tempHome, err := os.MkdirTemp("", "vane-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	_, _ = RunSingleTargetDiscovery("lo", "127.0.0.1", "")
}

func TestMergeIncomingRegistry(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "vane-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	iface := "eno1"

	// 1. Seed existing local registry cache entry
	entryLocal := CacheEntry{
		IP:              "192.168.178.50",
		MAC:             "aa:bb:cc:dd:ee:01",
		DiscoveryMethod: "passive",
		Name:            "Proxmox Primary",
	}
	err = UpdateCache(iface, "pve", entryLocal)
	if err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	// 2. Perform merge with an incoming registry map (JSON bytes)
	// Entry 'pve' has a different IP (conflict).
	// Entry 'nas' is brand new.
	incomingJSON := `{
		"pve": {
			"ip": "192.168.178.60",
			"mac": "aa:bb:cc:dd:ee:02",
			"discovery_method": "active",
			"name": "New Proxmox Master"
		},
		"nas": {
			"ip": "192.168.178.99",
			"mac": "aa:bb:cc:dd:ee:99",
			"discovery_method": "passive",
			"name": "Local Storage"
		}
	}`

	added, demoted, err := MergeIncomingRegistry([]byte(incomingJSON), iface)
	if err != nil {
		t.Fatalf("MergeIncomingRegistry failed: %v", err)
	}

	if added != 2 {
		t.Errorf("expected 2 added entries, got %d", added)
	}
	if demoted != 1 {
		t.Errorf("expected 1 demoted entry, got %d", demoted)
	}

	// 3. Verify merged cache entries
	merged, err := LoadCacheForInterface(iface)
	if err != nil {
		t.Fatalf("failed to load merged cache: %v", err)
	}

	// 'pve' should be the incoming one (192.168.178.60)
	if pve, ok := merged["pve"]; !ok || pve.IP != "192.168.178.60" {
		t.Errorf("expected primary 'pve' to be incoming IP '192.168.178.60', got %v", pve)
	}

	// 'pve.2' should exist and be the local seeded one (192.168.178.50)
	if pve2, ok := merged["pve.2"]; !ok || pve2.IP != "192.168.178.50" {
		t.Errorf("expected demoted 'pve.2' to have seeded IP '192.168.178.50', got %v", pve2)
	}

	// 'nas' should be the incoming one (192.168.178.99)
	if nas, ok := merged["nas"]; !ok || nas.IP != "192.168.178.99" {
		t.Errorf("expected brand new 'nas' to be '192.168.178.99', got %v", nas)
	}
}

func TestCacheSelfHealing(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "vane-home-corrupted-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	cacheFile := filepath.Join(tempHome, ".config", "vane", "cache.json")
	err = os.MkdirAll(filepath.Dir(cacheFile), 0700)
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	// Write corrupted JSON
	corruptedData := []byte(`{"invalid-json": [unclosed-array`)
	err = os.WriteFile(cacheFile, corruptedData, 0600)
	if err != nil {
		t.Fatalf("failed to write corrupted cache: %v", err)
	}

	// 1. Resolve from cache should fail gracefully and not panic
	ip, found := ResolveFromCache("eno1", "pve")
	if found || ip != "" {
		t.Errorf("expected miss on corrupted cache, got IP %q, found %t", ip, found)
	}

	// Verify corrupted backup file exists
	corruptedBackup := cacheFile + ".corrupted"
	if _, errStat := os.Stat(corruptedBackup); os.IsNotExist(errStat) {
		t.Errorf("expected backup file %s to exist, but was not found", corruptedBackup)
	}

	// Verify original corrupted file was removed to heal
	if _, errStat := os.Stat(cacheFile); !os.IsNotExist(errStat) {
		t.Errorf("expected original corrupted cache %s to be removed, but it still exists", cacheFile)
	}

	// 2. LoadCacheForInterface should also heal cleanly
	// Re-write corrupted JSON
	err = os.WriteFile(cacheFile, corruptedData, 0600)
	if err != nil {
		t.Fatalf("failed to write corrupted cache: %v", err)
	}

	resMap, errLoad := LoadCacheForInterface("eno1")
	if errLoad != nil {
		t.Errorf("expected no error from LoadCacheForInterface on corrupted cache, got: %v", errLoad)
	}
	if len(resMap) != 0 {
		t.Errorf("expected empty map from LoadCacheForInterface on corrupted cache, got: %v", resMap)
	}

	// Verify backup file exists again
	if _, errStat := os.Stat(corruptedBackup); os.IsNotExist(errStat) {
		t.Errorf("expected backup file %s to exist, but was not found", corruptedBackup)
	}
}
