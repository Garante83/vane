package scan

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanResult represents an active host found during the subnet scan
type ScanResult struct {
	IP        string
	IsAlive   bool
	OpenPorts []string
	MAC       string
}

// PerformScan executes a fast parallel sweep of the interface's subnet
func PerformScan(ifaceName string) error {
	// 1. Locate interface and IP
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to read addresses from %s: %w", ifaceName, err)
	}

	var localIP *net.IPNet
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			localIP = ipNet
			break
		}
	}

	if localIP == nil {
		return fmt.Errorf("no active IPv4 address found on interface %s", ifaceName)
	}

	// 2. Parse ARP table to prepopulate active MACs (instant detection)
	arpMap := parseARPTable(ifaceName)

	// 3. Resolve Default Gateway to flag it uniquely
	gatewayIP := getGatewayIP(ifaceName)

	// 4. Generate IP range to sweep
	ips := getSubnetIPs(localIP)
	if len(ips) == 0 {
		return fmt.Errorf("failed to calculate scan range for %s", localIP.String())
	}

	// Display scanning header
	fmt.Println("┌──────────────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│  vane scan ─ Subnet Discovery Matrix (Interface: %-26s) │\n", ifaceName)
	fmt.Println("└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Printf("  Scanning range %s (%d hosts) via fast TCP-peeking...\n\n", localIP.String(), len(ips))

	// 5. Parallel Sweep (Worker Pool)
	commonPorts := []string{"22", "80", "443", "445", "3389", "8080"}
	resultsChan := make(chan ScanResult, len(ips))
	ipsChan := make(chan string, len(ips))

	var wg sync.WaitGroup
	numWorkers := 45

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ipStr := range ipsChan {
				// Don't dial ourselves, we know we are alive!
				if ipStr == localIP.IP.String() {
					resultsChan <- ScanResult{
						IP:        ipStr,
						IsAlive:   true,
						OpenPorts: checkLocalPorts(commonPorts),
						MAC:       iface.HardwareAddr.String(),
					}
					continue
				}

				mac, inARP := arpMap[ipStr]
				alive, openPorts := peekHost(ipStr, commonPorts)

				if inARP {
					alive = true
				}

				resultsChan <- ScanResult{
					IP:        ipStr,
					IsAlive:   alive,
					OpenPorts: openPorts,
					MAC:       mac,
				}
			}
		}()
	}

	// Feed IPs to workers
	for _, ip := range ips {
		ipsChan <- ip.String()
	}
	close(ipsChan)

	// Start a background goroutine to close the results channel when workers finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Gather & sort alive results with a real-time progress spinner to keep the administrator informed
	var activeHosts []ScanResult
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	idx := 0
	count := 0
	total := len(ips)

	for res := range resultsChan {
		count++
		if res.IsAlive {
			activeHosts = append(activeHosts, res)
		}
		// Render real-time progress inline
		idx = (idx + 1) % len(spinner)
		fmt.Printf("\r  %s Sweeping subnet: %d/%d IPs processed... (found %d alive)", spinner[idx], count, total, len(activeHosts))
	}
	
	// Erase the progress line completely to render the final results cleanly
	fmt.Print("\r\x1b[K")

	sort.Slice(activeHosts, func(i, j int) bool {
		ip1 := net.ParseIP(activeHosts[i].IP)
		ip2 := net.ParseIP(activeHosts[j].IP)
		return bytes.Compare(ip1, ip2) < 0
	})

	// 6. Visual Tabular Output (Mathematically aligned, robust against ANSI escape length shifting)
	fmt.Printf("  %-16s %-8s %-16s %-16s %s\n", "IP ADDRESS", "STATUS", "PORT PEEK", "VANE-SYNTAX", "MAC / VENDOR")
	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")

	for _, host := range activeHosts {
		status := "[ UP ]"
		if host.IP == localIP.IP.String() {
			status = "[LOCAL]"
		} else if host.IP == gatewayIP {
			status = "[ GW ]"
		}

		// Pad raw status to exactly 8 characters first, then apply color
		statusPadded := fmt.Sprintf("%-8s", status)
		var statusColored string
		if host.IP == localIP.IP.String() {
			statusColored = "\x1b[1;34m" + statusPadded + "\x1b[0m" // Blue for LOCAL
		} else if host.IP == gatewayIP {
			statusColored = "\x1b[1;36m" + statusPadded + "\x1b[0m" // Cyan for GW
		} else {
			statusColored = "\x1b[1;32m" + statusPadded + "\x1b[0m" // Green for UP
		}

		// Format open ports elegantly with a strict truncation limit of 2 to preserve columns
		portsStr := formatPorts(host.OpenPorts)

		// Create Vane syntax suggestions
		syntax := "──"
		parts := strings.Split(host.IP, ".")
		if len(parts) == 4 {
			lastOctet := parts[3]
			if host.IP == gatewayIP {
				syntax = fmt.Sprintf("%s|>...gw", ifaceName)
			} else {
				syntax = fmt.Sprintf("%s|>...%s", ifaceName, lastOctet)
			}
		}

		// Pad raw syntax to exactly 16 characters first, then apply green color
		syntaxPadded := fmt.Sprintf("%-16s", syntax)
		syntaxColored := "\x1b[1;32m" + syntaxPadded + "\x1b[0m"

		// Format MAC & Vendor
		macVendor := "──"
		if host.MAC != "" {
			vendor := resolveVendor(host.MAC)
			if vendor != "" {
				macVendor = fmt.Sprintf("%s (%s)", host.MAC, vendor)
			} else {
				macVendor = host.MAC
			}
		}

		// Print with exact spacing matching the header
		fmt.Printf("  %-16s %s %-16s %s %s\n", host.IP, statusColored, portsStr, syntaxColored, macVendor)
	}

	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")

	fmt.Printf("  Discovered %d active hosts in subnet.\n", len(activeHosts))
	return nil
}

// formatPorts formats the active port array into a concise summary with a strict truncation limit
func formatPorts(openPorts []string) string {
	if len(openPorts) == 0 {
		return "──"
	}
	if len(openPorts) <= 2 {
		return "[" + strings.Join(openPorts, ",") + "]"
	}
	return "[" + strings.Join(openPorts[:2], ",") + ",...]"
}

// peekHost attempts to connect to standard ports using low-timeout TCP dial.
// Uses RST (Connection Refused) signature as host liveness proof.
func peekHost(ip string, ports []string) (bool, []string) {
	var openPorts []string
	var lock sync.Mutex
	var wg sync.WaitGroup
	alive := false

	for _, port := range ports {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			address := net.JoinHostPort(ip, p)
			conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
			if err == nil {
				conn.Close()
				lock.Lock()
				alive = true
				openPorts = append(openPorts, p)
				lock.Unlock()
			} else {
				// RST packet (Connection refused) proves machine is up and responding
				if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "refused") {
					lock.Lock()
					alive = true
					lock.Unlock()
				}
			}
		}(port)
	}

	wg.Wait()
	return alive, openPorts
}

// checkLocalPorts lists which scanned ports are currently listened to on the local machine
func checkLocalPorts(ports []string) []string {
	var open []string
	for _, port := range ports {
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			// Port is in use, therefore it's "open" on localhost
			open = append(open, port)
		} else {
			ln.Close()
		}
	}
	return open
}

// getSubnetIPs calculates all standard host addresses inside the CIDR block.
// Automatically caps massive subnets to a local /24 window for speed.
func getSubnetIPs(ipNet *net.IPNet) []net.IP {
	var ips []net.IP
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()

	// Restrict to /24 segment of active IP to guarantee sub-second scans
	if ones < 24 {
		ones = 24
	}

	numHosts := 1 << (bits - ones)
	startIP := make(net.IP, 4)
	copy(startIP, ip)
	for i := 0; i < 4; i++ {
		startIP[i] = startIP[i] & mask[i]
	}

	// Adjust base if forced /24 on wider address spaces
	if ones == 24 && ipNet.Mask[2] != 255 {
		startIP[2] = ip[2]
	}

	for i := 0; i < numHosts; i++ {
		nextIP := make(net.IP, 4)
		copy(nextIP, startIP)

		val := uint32(nextIP[0])<<24 | uint32(nextIP[1])<<16 | uint32(nextIP[2])<<8 | uint32(nextIP[3])
		val += uint32(i)

		nextIP[0] = byte(val >> 24)
		nextIP[1] = byte(val >> 16)
		nextIP[2] = byte(val >> 8)
		nextIP[3] = byte(val)

		// Omit network ID (.0) and broadcast (.255)
		if nextIP[3] == 0 || nextIP[3] == 255 {
			continue
		}

		ips = append(ips, nextIP)
	}

	return ips
}

// parseARPTable parses Linux /proc/net/arp to fetch hardware addresses.
func parseARPTable(ifaceName string) map[string]string {
	arpMap := make(map[string]string)

	data, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for i := 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				ip := fields[0]
				mac := fields[3]
				dev := fields[5]
				if dev == ifaceName && mac != "00:00:00:00:00:00" {
					arpMap[ip] = mac
				}
			}
		}
	}

	return arpMap
}

// getGatewayIP scans routing tables to fetch the gateway IP
func getGatewayIP(ifaceName string) string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		iface := fields[0]
		dest := fields[1]
		gwHex := fields[2]

		if iface == ifaceName && dest == "00000000" && gwHex != "00000000" {
			// Convert hex little-endian
			if len(gwHex) == 8 {
				var ipBytes [4]byte
				for j := 0; j < 4; j++ {
					start := 6 - j*2
					val := 0
					fmt.Sscanf(gwHex[start:start+2], "%x", &val)
					ipBytes[j] = byte(val)
				}
				return fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
			}
		}
	}
	return ""
}

// resolveVendor translates MAC OUIs into human-readable manufacturer names
func resolveVendor(mac string) string {
	macClean := strings.ToLower(strings.ReplaceAll(mac, ":", ""))
	if len(macClean) < 6 {
		return ""
	}
	oui := macClean[:6]

	vendors := map[string]string{
		"b827eb": "Raspberry Pi",
		"dca632": "Raspberry Pi",
		"e45f01": "Raspberry Pi",
		"000c29": "VMware",
		"000569": "VMware",
		"005056": "VMware",
		"080027": "VirtualBox",
		"00155d": "Microsoft",
		"001c42": "Parallels",
		"7085c2": "AVM Fritz!Box",
		"fcecda": "Ubiquiti",
		"acbc32": "Apple",
		"f4f5d8": "Google",
		"3c3712": "Huawei",
		"74ac5f": "Intel",
		"d4619d": "Intel",
		"001a11": "Intel",
	}

	if name, ok := vendors[oui]; ok {
		return name
	}
	return ""
}
