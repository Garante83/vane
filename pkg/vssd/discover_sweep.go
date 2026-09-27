//go:build !nosweep
// +build !nosweep

package vssd

import (
	"strings"
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

	candidates := make(map[string][]CacheEntry)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Spin up a small worker pool to verify only these specific active targets
	for ip, mac := range targets {
		wg.Add(1)
		go func(targetIP, targetMAC string) {
			defer wg.Done()
			localResults := make(map[string]CacheEntry)
			var localMu sync.Mutex
			matchHost(targetIP, targetMAC, cacheMap, &localResults, &localMu)

			mu.Lock()
			for tok, entry := range localResults {
				candidates[tok] = append(candidates[tok], entry)
			}
			mu.Unlock()
		}(ip, mac)
	}

	wg.Wait()

	// Post-processing deduplication and prioritization pass:
	results := make(map[string]CacheEntry)

	// A. Identify which IPs host a reverse proxy (rpx) to avoid false-positive service hijacking
	isProxyIP := make(map[string]bool)
	for _, entry := range candidates["rpx"] {
		isProxyIP[entry.IP] = true
	}

	// B. Filter candidates: if an IP has a Proxmox virtual MAC and hosts both rpx and pve, discard pve on this IP
	for tok, entries := range candidates {
		if tok == "pve" {
			var filtered []CacheEntry
			for _, entry := range entries {
				cleanMAC := strings.ToLower(strings.ReplaceAll(entry.MAC, ":", ""))
				isProxmoxVM := strings.HasPrefix(cleanMAC, "bc2411")
				if isProxmoxVM && isProxyIP[entry.IP] {
					// Discard this candidate because it's a proxy VM running on Proxmox, not the real PVE host
					continue
				}
				filtered = append(filtered, entry)
			}
			candidates[tok] = filtered
		}
	}

	// C. Select the single best candidate IP for each token
	for tok, entries := range candidates {
		if len(entries) == 0 {
			continue
		}
		if len(entries) == 1 {
			results[tok] = entries[0]
			continue
		}

		bestEntry := entries[0]
		sig, hasSig := FindSignature(tok)

		for i := 1; i < len(entries); i++ {
			candidate := entries[i]
			replace := false

			// 1. MAC OUI check (if signature has OUI prefixes, physical match is high confidence)
			if hasSig && len(sig.MACOUIPrefixes) > 0 {
				candHasMAC := false
				bestHasMAC := false

				cleanCandMAC := strings.ToLower(strings.ReplaceAll(candidate.MAC, ":", ""))
				cleanBestMAC := strings.ToLower(strings.ReplaceAll(bestEntry.MAC, ":", ""))

				for _, prefix := range sig.MACOUIPrefixes {
					cleanPrefix := strings.ToLower(strings.ReplaceAll(prefix, ":", ""))
					if strings.HasPrefix(cleanCandMAC, cleanPrefix) {
						candHasMAC = true
					}
					if strings.HasPrefix(cleanBestMAC, cleanPrefix) {
						bestHasMAC = true
					}
				}

				if candHasMAC && !bestHasMAC {
					replace = true
				} else if !candHasMAC && bestHasMAC {
					continue
				}
			}

			// 2. Reverse Proxy Avoidance: Prefer direct host over proxy IP
			if isProxyIP[bestEntry.IP] && !isProxyIP[candidate.IP] {
				replace = true
			} else if !isProxyIP[bestEntry.IP] && isProxyIP[candidate.IP] {
				continue
			}

			// 3. Fallback: Prefer candidate with valid MAC address if bestEntry has none
			if bestEntry.MAC == "" && candidate.MAC != "" {
				replace = true
			}

			if replace {
				bestEntry = candidate
			}
		}

		results[tok] = bestEntry
	}

	return results, nil
}
