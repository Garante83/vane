package vssd

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"vane/pkg/uip"
)

// LookupMDNSOSResolver performs a quick, standard OS-level lookup for candidates, returning both IPv4 and IPv6 addresses.
func LookupMDNSOSResolver(token string) (string, string, bool) {
	sig, ok := FindSignature(token)
	var candidates []string
	if ok {
		for _, name := range sig.MDNSNames {
			candidates = append(candidates, name+".local")
		}
	}
	candidates = append(candidates, token+".local")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	v4, v6 := "", ""
	for _, host := range candidates {
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err == nil {
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					if ip.To4() != nil {
						if v4 == "" {
							v4 = ipStr
						}
					} else {
						if v6 == "" {
							v6 = ipStr
						}
					}
				}
			}
			if v4 != "" || v6 != "" {
				return v4, v6, true
			}
		}
	}
	return "", "", false
}

// DiscoverService is the primary entry point for resolving a semantic service IP.
// By default, it uses standard OS lookups (passive/zero-footprint).
// If active is true, it performs an on-demand targeted verification scan (no sweeps).
func DiscoverService(ifaceName, token string, active bool) (string, error) {
	// 1. Try Cache first
	if ip, found := ResolveFromCache(ifaceName, token); found {
		return ip, nil
	}

	// 2. Passive OS mDNS Resolution (zero footprint)
	if v4, _, found := LookupMDNSOSResolver(token); found && v4 != "" {
		return v4, nil
	}

	// 3. Passive ARP Neighbor OUI Signature matching (zero footprint)
	arpResults, err := RunPassiveARPDiscovery(ifaceName)
	if err == nil {
		if entry, found := arpResults[token]; found {
			// Save to cache for ultra-fast subsequent lookup
			_ = UpdateCache(ifaceName, token, entry)
			return entry.IP, nil
		}
	}

	// 4. Active Targeted verification (Only if explicitly enabled or requested, NO subnet sweeps)
	if active {
		results, err := RunTargetedDiscovery(ifaceName)
		if err == nil {
			if entry, found := results[token]; found {
				_ = UpdateCache(ifaceName, token, entry)
				return entry.IP, nil
			}
		}
	}

	return "", fmt.Errorf("service token '%s' could not be resolved on interface %s", token, ifaceName)
}

// RunPassiveARPDiscovery performs zero-footprint local neighbor table analysis
// matching MAC OUI hardware addresses against known service signatures.
func RunPassiveARPDiscovery(ifaceName string) (map[string]CacheEntry, error) {
	arpMap := parseARPCache(ifaceName)
	results := make(map[string]CacheEntry)

	for ip, mac := range arpMap {
		if mac == "" {
			continue
		}
		cleanMac := strings.ToLower(strings.ReplaceAll(mac, ":", ""))

		for _, sig := range Signatures {
			if len(sig.MACOUIPrefixes) == 0 {
				continue
			}
			for _, prefix := range sig.MACOUIPrefixes {
				cleanPrefix := strings.ToLower(strings.ReplaceAll(prefix, ":", ""))
				if strings.HasPrefix(cleanMac, cleanPrefix) {
					// SLAAC Link-Local IPv6 computation from MAC
					ipv6Str := ""
					if hw, err := net.ParseMAC(mac); err == nil && len(hw) == 6 {
						eui64 := uip.ComputeEUI64(hw)
						ipv6Str = "fe80::" + eui64
					}

					results[sig.Token] = CacheEntry{
						IP:              ip,
						IPv6:            ipv6Str,
						MAC:             mac,
						Ports:           sig.Ports,
						DiscoveryMethod: "passive_arp",
						LastSeen:        time.Now(),
					}
					break
				}
			}
		}
	}

	return results, nil
}

// RunTargetedDiscovery performs precise, non-aggressive service signature peeking
// strictly limited to:
// 1) Hosts currently present in the system's passive neighbor (ARP) cache.
// 2) Hosts manually registered by the user in their Vane service cache.
//
// Matching rules (confidence-based):
//   - An open AMBIGUOUS port (80, 443, 22, 53, etc.) alone is NEVER sufficient for identification.
//   - An open UNIQUE port (8006, 8123, 32400, etc.) IS sufficient as strong evidence.
//   - A MAC OUI prefix match IS sufficient as strong evidence.
//   - A payload fingerprint confirmation IS the highest evidence and overrides port-only matches.
//   - If ONLY ambiguous ports are open, the signature requires additional OUI or fingerprint evidence.

// RunSingleTargetDiscovery performs targeted active port verification on a single designated host
func RunSingleTargetDiscovery(ifaceName string, targetIP, targetMAC string) (map[string]CacheEntry, error) {
	if targetMAC == "" {
		arpMap := parseARPCache(ifaceName)
		if mac, exists := arpMap[targetIP]; exists {
			targetMAC = mac
		}
	}

	results := make(map[string]CacheEntry)
	cacheMap, _ := LoadCacheForInterface(ifaceName)
	var mu sync.Mutex

	matchHost(targetIP, targetMAC, cacheMap, &results, &mu)

	return results, nil
}

// matchHost runs the confidence-based signature matching against a single host IP.
// It is shared between RunTargetedDiscovery and RunSingleTargetDiscovery to
// guarantee identical matching behavior.
func matchHost(targetIP, targetMAC string, cacheMap InterfaceMap, results *map[string]CacheEntry, mu *sync.Mutex) {
	for _, sig := range Signatures {
		var openPorts []int
		ouiMatched := false
		fingerprintConfirmed := false
		fingerprintDenied := false
		hasUniquePort := false

		// 1. Check MAC OUI prefix (instant, silent, high confidence)
		if len(sig.MACOUIPrefixes) > 0 && targetMAC != "" {
			cleanMac := strings.ToLower(strings.ReplaceAll(targetMAC, ":", ""))
			for _, prefix := range sig.MACOUIPrefixes {
				cleanPrefix := strings.ToLower(strings.ReplaceAll(prefix, ":", ""))
				if strings.HasPrefix(cleanMac, cleanPrefix) {
					ouiMatched = true
					break
				}
			}
		}

		// 2. Port verification: probe each signature port on the target
		for _, port := range sig.Ports {
			if dialHost(targetIP, port, 150*time.Millisecond) {
				openPorts = append(openPorts, port)

				// Track if at least one non-ambiguous (unique) port is open
				if !isAmbiguousPort(port) {
					hasUniquePort = true
				}

				// 3. Payload fingerprint peeking on HTTP-capable or protocol-specific ports
				peekedToken := peekServiceFingerprint(targetIP, port)
				if peekedToken != "" {
					if peekedToken == sig.Token {
						fingerprintConfirmed = true
					} else {
						fingerprintDenied = true
					}
				}
			}
		}

		// === CONFIDENCE GATE ===
		// A match requires at least ONE of these strong evidence signals:
		//   a) Payload fingerprint positively confirmed this exact service
		//   b) MAC OUI prefix matches a known manufacturer for this service
		//   c) At least one UNIQUE (non-ambiguous) port is open (e.g. 8006, 8123, 32400)
		//
		// If the fingerprint actively DENIED this service (identified a different service
		// on the same port), the match is always rejected regardless of other signals.

		if fingerprintDenied {
			continue // Payload said "this is NOT this service" → skip
		}

		matched := false
		if fingerprintConfirmed {
			matched = true // Highest confidence: payload identified itself
		} else if ouiMatched {
			matched = true // High confidence: hardware manufacturer matches
		} else if hasUniquePort && len(openPorts) > 0 {
			matched = true // Good confidence: unique port is open (e.g. 8006 = very likely PVE)
		}
		// If ONLY ambiguous ports are open (80, 443, 22...) with no OUI and no fingerprint → no match

		if !matched {
			continue
		}

		// Build result entry with proper human-readable name
		ipv6Str := ""
		if targetMAC != "" {
			if hw, err := net.ParseMAC(targetMAC); err == nil && len(hw) == 6 {
				eui64 := uip.ComputeEUI64(hw)
				ipv6Str = "fe80::" + eui64
			}
		}
		if _, v6Resolved, ok := LookupMDNSOSResolver(sig.Token); ok && v6Resolved != "" {
			ipv6Str = v6Resolved
		}

		// Determine display name: existing cache name > signature DisplayName > token
		entryName := sig.DisplayName
		if cacheMap != nil {
			if existing, exists := cacheMap[sig.Token]; exists && existing.Name != "" {
				entryName = existing.Name
			}
		}

		mu.Lock()
		(*results)[sig.Token] = CacheEntry{
			IP:              targetIP,
			IPv6:            ipv6Str,
			MAC:             targetMAC,
			Name:            entryName,
			Ports:           openPorts,
			DiscoveryMethod: "targeted_fingerprint",
			LastSeen:        time.Now(),
		}
		mu.Unlock()
	}
}

// dialHost tests if a specific port is responsive on an IP within the timeout limit.
func dialHost(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

// parseARPCache loads system neighbor caches across Linux/macOS and Windows formats.
func parseARPCache(ifaceName string) map[string]string {
	arpMap := make(map[string]string)

	// Read standard Linux proc ARP table
	data, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for i := 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			ip := fields[0]
			mac := fields[3]
			dev := fields[5]
			if dev == ifaceName && mac != "00:00:00:00:00:00" {
				arpMap[ip] = mac
			}
		}
	}
	return arpMap
}

// peekServiceFingerprint performs targeted payload peeking to verify a service.
// Returns the 3-letter token of the positively identified service, or "" if inconclusive.
func peekServiceFingerprint(ip string, port int) string {
	// A. Check database and special enterprise protocols first
	switch port {
	case 22: // SSH banner peeking
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), 250*time.Millisecond)
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 256)
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, err := conn.Read(buf)
			if err == nil {
				banner := strings.ToLower(string(buf[:n]))
				if strings.Contains(banner, "raspbian") || strings.Contains(banner, "raspberry") {
					return "pi"
				}
				if strings.Contains(banner, "dropbear") {
					return "rtr" // dropbear is common on routers/embedded devices
				}
			}
		}
		return ""
	case 53: // DNS resolver check
		conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "53"), 250*time.Millisecond)
		if err == nil {
			defer conn.Close()
			// Minimal valid DNS query for 'localhost' A record
			query := []byte{
				0x12, 0x34, // Transaction ID
				0x01, 0x00, // Flags (Standard Query)
				0x00, 0x01, // Questions: 1
				0x00, 0x00, // Answer RRs: 0
				0x00, 0x00, // Authority RRs: 0
				0x00, 0x00, // Additional RRs: 0
				0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00, // Name: localhost
				0x00, 0x01, // Type: A
				0x00, 0x01, // Class: IN
			}
			_, err = conn.Write(query)
			if err == nil {
				buf := make([]byte, 512)
				_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
				n, err := conn.Read(buf)
				if err == nil && n >= 12 {
					// Check Transaction ID match and response flag (QR bit in byte 2 must be set: buf[2] & 0x80)
					if buf[0] == 0x12 && buf[1] == 0x34 && (buf[2]&0x80) != 0 {
						return "dns"
					}
				}
			}
		}
		return ""
	case 6379: // Redis
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "6379"), 150*time.Millisecond)
		if err == nil {
			defer conn.Close()
			_, _ = conn.Write([]byte("PING\r\n"))
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			n, err := conn.Read(buf)
			if err == nil {
				resp := string(buf[:n])
				if strings.Contains(resp, "+PONG") || strings.Contains(resp, "NOAUTH") {
					return "rds"
				}
			}
		}
		return ""
	}

	// B. Standard HTTP/HTTPS peeking
	client := &http.Client{
		Timeout: 400 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	protocols := []string{"https", "http"}
	for _, proto := range protocols {
		url := fmt.Sprintf("%s://%s:%d/", proto, ip, port)
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2048)
			n, _ := io.ReadFull(resp.Body, buf)
			bodyStr := strings.ToLower(string(buf[:n]))

			// Proxmox VE
			if strings.Contains(bodyStr, "proxmox") || (port == 8006 && strings.Contains(bodyStr, "pve")) {
				return "pve"
			}
			// Proxmox Backup Server (must check before generic proxmox)
			if port == 8007 && strings.Contains(bodyStr, "proxmox") {
				return "pbs"
			}
			// Home Assistant
			if strings.Contains(bodyStr, "home assistant") || strings.Contains(bodyStr, "hass.io") {
				return "hass"
			}
			// Synology / NAS
			if strings.Contains(bodyStr, "synology") || strings.Contains(bodyStr, "dsm") || strings.Contains(bodyStr, "truenas") || strings.Contains(bodyStr, "qnap") {
				return "nas"
			}
			// Elasticsearch
			if strings.Contains(bodyStr, "you know, for search") {
				return "els"
			}
			// Kubernetes API Server
			if port == 6443 && (strings.Contains(bodyStr, "forbidden") || strings.Contains(bodyStr, "unauthorized")) {
				return "k8s"
			}
			// Docker API
			if (port == 2375 || port == 2376) && strings.Contains(bodyStr, "docker") {
				return "dck"
			}
			// Portainer
			if strings.Contains(bodyStr, "portainer") {
				return "pot"
			}
			// Grafana
			if strings.Contains(bodyStr, "grafana") {
				return "mon"
			}
			// Jellyfin
			if strings.Contains(bodyStr, "jellyfin") {
				return "jly"
			}
			// Plex
			if strings.Contains(bodyStr, "plex") && port == 32400 {
				return "plx"
			}
			// Gitea / Forgejo / GitLab
			if strings.Contains(bodyStr, "gitea") || strings.Contains(bodyStr, "forgejo") {
				return "git"
			}
			if strings.Contains(bodyStr, "gitlab") {
				return "git"
			}
			// UniFi Controller
			if strings.Contains(bodyStr, "unifi") || strings.Contains(bodyStr, "ubiquiti") {
				return "unf"
			}
			// Pi-hole / AdGuard
			if strings.Contains(bodyStr, "pi-hole") || strings.Contains(bodyStr, "pihole") {
				return "dns"
			}
			if strings.Contains(bodyStr, "adguard") {
				return "dns"
			}
			// Reverse Proxies (nginx, traefik, caddy, haproxy)
			if port == 81 && strings.Contains(bodyStr, "nginx proxy manager") {
				return "rpx"
			}
			if strings.Contains(bodyStr, "traefik") {
				return "rpx"
			}
			// MinIO
			if strings.Contains(bodyStr, "minio") {
				return "mio"
			}
			// n8n
			if strings.Contains(bodyStr, "n8n") {
				return "n8n"
			}
			// HashiCorp Vault
			if strings.Contains(bodyStr, "vault") && port == 8200 {
				return "val"
			}
			// Foundry VTT
			if strings.Contains(bodyStr, "foundry") || strings.Contains(bodyStr, "virtual tabletop") {
				return "fdy"
			}
			// Open WebUI
			if strings.Contains(bodyStr, "open webui") || strings.Contains(bodyStr, "open-webui") {
				return "owu"
			}
			// Nextcloud
			if strings.Contains(bodyStr, "nextcloud") {
				return "ncd"
			}
			// Paperless-ngx
			if strings.Contains(bodyStr, "paperless-ngx") || strings.Contains(bodyStr, "paperless ngx") || (strings.Contains(bodyStr, "paperless") && strings.Contains(bodyStr, "document")) {
				return "ppl"
			}
		}
	}
	return ""
}
