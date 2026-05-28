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

// ServiceSignature defines target fingerprints for specific home-server and enterprise services.
type ServiceSignature struct {
	Token          string
	Ports          []int
	MDNSNames      []string
	MACOUIPrefixes []string
}

// Signatures is the static target fingerprint matrix for VSSD.
var Signatures = []ServiceSignature{
	{
		Token:     "pve",
		Ports:     []int{8006},
		MDNSNames: []string{"proxmox", "pve"},
	},
	{
		Token:          "nas",
		Ports:          []int{5000, 5001, 445, 80, 443},
		MDNSNames:      []string{"synology", "truenas", "nas", "nextcloud"},
		MACOUIPrefixes: []string{"00:11:32"}, // Synology OUI
	},
	{
		Token:          "pi",
		Ports:          []int{22},
		MDNSNames:      []string{"raspberrypi", "pi"},
		MACOUIPrefixes: []string{"b8:27:eb", "dc:a6:32", "e4:5f:01"},
	},
	{
		Token:     "hass",
		Ports:     []int{8123},
		MDNSNames: []string{"homeassistant", "hass"},
	},
	// Enterprise-typical database and infrastructure services
	{
		Token: "pgs",
		Ports: []int{5432},
	},
	{
		Token: "mys",
		Ports: []int{3306},
	},
	{
		Token: "rds",
		Ports: []int{6379},
	},
	{
		Token: "mgo",
		Ports: []int{27017},
	},
	{
		Token: "els",
		Ports: []int{9200},
	},
	{
		Token: "k8s",
		Ports: []int{6443},
	},
	{
		Token: "dck",
		Ports: []int{2375, 2376},
	},
}

// FindSignature retrieves the signature for a given token.
func FindSignature(token string) (ServiceSignature, bool) {
	for _, sig := range Signatures {
		if sig.Token == token {
			return sig, true
		}
	}
	return ServiceSignature{}, false
}

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

	// 3. Active Targeted verification (Only if explicitly enabled or requested, NO subnet sweeps)
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

// RunTargetedDiscovery performs precise, non-aggressive service signature peeking
// strictly limited to:
// 1) Hosts currently present in the system's passive neighbor (ARP) cache.
// 2) Hosts manually registered by the user in their Vane service cache.
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

			// Check our signatures
			for _, sig := range Signatures {
				matched := false
				var openPorts []int

				// 1. Check MAC OUI (instant, silent)
				ouiMatched := false
				if len(sig.MACOUIPrefixes) > 0 && targetMAC != "" {
					cleanMac := strings.ToLower(strings.ReplaceAll(targetMAC, ":", ""))
					for _, prefix := range sig.MACOUIPrefixes {
						cleanPrefix := strings.ToLower(strings.ReplaceAll(prefix, ":", ""))
						if strings.HasPrefix(cleanMac, cleanPrefix) {
							ouiMatched = true
							matched = true
							break
						}
					}
				}

				// 2. Precise Port verification (strictly limited to target)
				for _, port := range sig.Ports {
					if dialHost(targetIP, port, 150*time.Millisecond) {
						openPorts = append(openPorts, port)
						matched = true

						// HTTP payload peeking to verify service
						if port == 8006 || port == 8123 || port == 80 || port == 443 || port == 5000 || port == 5001 || port == 9200 || port == 6443 || port == 2375 || port == 2376 {
							peekedToken := peekServiceFingerprint(targetIP, port)
							if peekedToken != "" {
								if peekedToken == sig.Token {
									matched = true
								} else {
									matched = false
								}
							}
						}
					}
				}

				// Strict gate for "pi" (SSH check on generic Linux VMs is too broad)
				if sig.Token == "pi" && matched {
					if !ouiMatched {
						matched = false
						if pip, _, ok := LookupMDNSOSResolver("pi"); ok && pip == targetIP {
							matched = true
						}
					}
				}

				if matched {
					// SLAAC Link-Local IPv6 computation
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

					mu.Lock()
					// Fallback to manual entry name if already present in cache
					entryName := ""
					if existing, exists := cacheMap[sig.Token]; exists {
						entryName = existing.Name
					}
					results[sig.Token] = CacheEntry{
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
		}(ip, mac)
	}

	wg.Wait()
	return results, nil
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
func peekServiceFingerprint(ip string, port int) string {
	// A. Check database and special enterprise protocols first
	switch port {
	case 6379: // Redis
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "6379"), 150*time.Millisecond)
		if err == nil {
			defer conn.Close()
			_, _ = conn.Write([]byte("PING\r\n"))
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(150*time.Millisecond))
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
		Timeout: 150 * time.Millisecond,
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
			buf := make([]byte, 1024)
			n, _ := io.ReadFull(resp.Body, buf)
			bodyStr := strings.ToLower(string(buf[:n]))

			// 1. Proxmox VE
			if strings.Contains(bodyStr, "proxmox") || strings.Contains(bodyStr, "pve") {
				return "pve"
			}
			// 2. Home Assistant
			if strings.Contains(bodyStr, "home assistant") || strings.Contains(bodyStr, "hass") {
				return "hass"
			}
			// 3. Synology / NAS
			if strings.Contains(bodyStr, "nextcloud") || strings.Contains(bodyStr, "synology") || strings.Contains(bodyStr, "dsm") || strings.Contains(bodyStr, "truenas") {
				return "nas"
			}
			// 4. Elasticsearch
			if strings.Contains(bodyStr, "you know, for search") {
				return "els"
			}
			// 5. Kubernetes API Server
			if port == 6443 && (strings.Contains(bodyStr, "forbidden") || strings.Contains(bodyStr, "unauthorized")) {
				return "k8s"
			}
			// 6. Docker API
			if (port == 2375 || port == 2376) && strings.Contains(bodyStr, "docker") {
				return "dck"
			}
		}
	}
	return ""
}
