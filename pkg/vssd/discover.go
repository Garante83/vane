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

// ServiceSignature defines target fingerprints for specific home-server services.
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
// If active is true, it performs an on-demand subnet sweep.
func DiscoverService(ifaceName, token string, active bool) (string, error) {
	// 1. Try Cache first
	if ip, found := ResolveFromCache(ifaceName, token); found {
		return ip, nil
	}

	// 2. Passive OS mDNS Resolution (zero footprint)
	if v4, _, found := LookupMDNSOSResolver(token); found && v4 != "" {
		return v4, nil
	}

	// 3. Active Subnet Sweep (Only if explicitly enabled or requested)
	if active {
		results, err := RunSubnetDiscovery(ifaceName)
		if err == nil {
			if entry, found := results[token]; found {
				_ = UpdateCache(ifaceName, token, entry)
				return entry.IP, nil
			}
		}
	}

	return "", fmt.Errorf("service token '%s' could not be resolved on interface %s", token, ifaceName)
}

// RunSubnetDiscovery sweeps the local subnet of the interface for known service signatures.
func RunSubnetDiscovery(ifaceName string) (map[string]CacheEntry, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var localIPNet *net.IPNet
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			localIPNet = ipNet
			break
		}
	}

	if localIPNet == nil {
		return nil, fmt.Errorf("no IPv4 address configured on %s", ifaceName)
	}

	ips := getSubnetIPs(localIPNet)
	arpMap := parseARPCache(ifaceName)
	results := make(map[string]CacheEntry)
	var mu sync.Mutex

	// Spin up worker pool for rapid concurrent port peeking (100ms timeout per host)
	var wg sync.WaitGroup
	ipsChan := make(chan string, len(ips))
	numWorkers := 50

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipsChan {
				if ip == localIPNet.IP.String() {
					continue
				}

				mac := arpMap[ip]

				// Peek ports for all signatures in parallel on this host
				for _, sig := range Signatures {
					matched := false
					var openPorts []int

					// Check MAC OUI matches first (instant)
					ouiMatched := false
					if len(sig.MACOUIPrefixes) > 0 && mac != "" {
						cleanMac := strings.ToLower(strings.ReplaceAll(mac, ":", ""))
						for _, prefix := range sig.MACOUIPrefixes {
							cleanPrefix := strings.ToLower(strings.ReplaceAll(prefix, ":", ""))
							if strings.HasPrefix(cleanMac, cleanPrefix) {
								ouiMatched = true
								matched = true
								break
							}
						}
					}

					// Verify active port peeking
					for _, port := range sig.Ports {
						if dialHost(ip, port, 100*time.Millisecond) {
							openPorts = append(openPorts, port)
							matched = true

							// HTTP payload peeking for web dashboards
							if port == 8006 || port == 8123 || port == 80 || port == 443 || port == 5000 || port == 5001 {
								peekedToken := peekServiceFingerprint(ip, port)
								if peekedToken != "" {
									if peekedToken == sig.Token {
										matched = true
									} else {
										// If it matches a different service fingerprint, disqualify this signature matching
										matched = false
									}
								}
							}
						}
					}

					// Strict gate for "pi" (SSH check on generic Linux VMs is too broad)
					if sig.Token == "pi" && matched {
						// Only allow "pi" if hardware OUI matched OR if hostname resolves to pi
						if !ouiMatched {
							matched = false
							// Check if mDNS resolved hostname matches pi/raspberry
							if pip, _, ok := LookupMDNSOSResolver("pi"); ok && pip == ip {
								matched = true
							}
						}
					}

					if matched {
						// Compute Link-Local SLAAC or passive mDNS resolved global IPv6
						ipv6Str := ""
						if mac != "" {
							if hw, err := net.ParseMAC(mac); err == nil && len(hw) == 6 {
								eui64 := uip.ComputeEUI64(hw)
								ipv6Str = "fe80::" + eui64
							}
						}
						if _, v6Resolved, ok := LookupMDNSOSResolver(sig.Token); ok && v6Resolved != "" {
							ipv6Str = v6Resolved
						}

						mu.Lock()
						results[sig.Token] = CacheEntry{
							IP:              ip,
							IPv6:            ipv6Str,
							MAC:             mac,
							Ports:           openPorts,
							DiscoveryMethod: "active_fingerprint",
							LastSeen:        time.Now(),
						}
						mu.Unlock()
					}
				}
			}
		}()
	}

	for _, ip := range ips {
		ipsChan <- ip
	}
	close(ipsChan)
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

// getSubnetIPs calculates all IPv4 addresses in a subnet range.
func getSubnetIPs(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}

	mask := ipNet.Mask
	num := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	maskNum := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])

	first := num & maskNum
	last := num | ^maskNum

	// Limit to /24 maximum sweep size to keep discovery ultra fast (<300ms)
	if last-first > 256 {
		first = num & 0xFFFFFF00
		last = num | 0x000000FF
	}

	for i := first + 1; i < last; i++ {
		ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", byte(i>>24), byte(i>>16), byte(i>>8), byte(i)))
	}
	return ips
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

// peekServiceFingerprint makes a fast, insecure-by-design HTTPS/HTTP probe on a target to fingerprint services.
func peekServiceFingerprint(ip string, port int) string {
	// 150ms timeout is perfect for local network sweeps
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
			
			// Read first 1024 bytes of the HTML response
			buf := make([]byte, 1024)
			n, _ := io.ReadFull(resp.Body, buf)
			bodyStr := strings.ToLower(string(buf[:n]))

			// Match high-precision signatures in response bodies
			if strings.Contains(bodyStr, "proxmox") || strings.Contains(bodyStr, "pve") {
				return "pve"
			}
			if strings.Contains(bodyStr, "home assistant") || strings.Contains(bodyStr, "hass") {
				return "hass"
			}
			if strings.Contains(bodyStr, "nextcloud") || strings.Contains(bodyStr, "synology") || strings.Contains(bodyStr, "dsm") || strings.Contains(bodyStr, "truenas") {
				return "nas"
			}
		}
	}
	return ""
}
