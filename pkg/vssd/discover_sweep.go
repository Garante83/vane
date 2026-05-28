//go:build !nosweep
// +build !nosweep

package vssd

import (
	"sync"
)

// RunTargetedDiscovery performs active port verification on all alive ARP neighbors.
// This is enabled in the standard (home/private) version of Vane.
func RunTargetedDiscovery(ifaceName string) (map[string]CacheEntry, error) {
	// A. Get local interface and passive ARP neighbors
	arpMap := parseARPCache(ifaceName)

	// B. Also collect manually registered hosts from the local Vane cache
	manualIPs := make(map[string]bool)
	cacheMap, err := LoadCacheForInterface(ifaceName)
	if err == nil {
		for _, entry := range cacheMap {
			if entry.IP != "" {
				manualIPs[entry.IP] = true
			}
		}
	}

	// C. Combine all safe target IPs (no blind range sweeps!)
	targets := make(map[string]string) // IP -> MAC
	for ip, mac := range arpMap {
		targets[ip] = mac
	}
	for ip := range manualIPs {
		if _, exists := targets[ip]; !exists {
			targets[ip] = "" // No MAC known yet
		}
	}

	results := make(map[string]CacheEntry)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Spin up a small worker pool to verify only these specific active targets
	for ip, mac := range targets {
		wg.Add(1)
		go func(targetIP, targetMAC string) {
			defer wg.Done()
			matchHost(targetIP, targetMAC, cacheMap, &results, &mu)
		}(ip, mac)
	}

	wg.Wait()
	return results, nil
}
