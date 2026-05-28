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

// ScanResult represents an active host found during the neighbor scan
type ScanResult struct {
	IP        string
	IsAlive   bool
	OpenPorts []string
	MAC       string
}

// PerformScan executes a fast parallel targeted check of known active neighbor hosts
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

	// 4. Generate target IPs (strictly limited to active neighbor cache, self and gateway)
	targets := make(map[string]string) // IP -> MAC
	for ip, mac := range arpMap {
		targets[ip] = mac
	}
	// Add self
	targets[localIP.IP.String()] = iface.HardwareAddr.String()
	// Add gateway
	if gatewayIP != "" {
		if _, exists := targets[gatewayIP]; !exists {
			targets[gatewayIP] = ""
		}
	}

	// Display scanning header
	fmt.Println("┌──────────────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│  vane scan ─ Neighbor Discovery Matrix (Interface: %-26s) │\n", ifaceName)
	fmt.Println("└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Printf("  Scanning %d active neighbors from ARP cache via targeted TCP-peeking...\n\n", len(targets))

	// 5. Parallel targeted checks (Worker Pool)
	commonPorts := []string{"22", "80", "443", "445", "3389", "8080"}
	resultsChan := make(chan ScanResult, len(targets))
	targetsChan := make(chan string, len(targets))

	var wg sync.WaitGroup
	numWorkers := 10

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ipStr := range targetsChan {
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

				mac := targets[ipStr]
				alive, openPorts := peekHost(ipStr, commonPorts)

				if mac != "" {
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

	// Feed active target IPs to workers
	for ip := range targets {
		targetsChan <- ip
	}
	close(targetsChan)

	// Start a background goroutine to close the results channel when workers finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Gather & sort alive results with a real-time progress spinner
	var activeHosts []ScanResult
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	idx := 0
	count := 0
	total := len(targets)

	for res := range resultsChan {
		count++
		if res.IsAlive {
			activeHosts = append(activeHosts, res)
		}
		// Render real-time progress inline
		idx = (idx + 1) % len(spinner)
		fmt.Printf("\r  %s Verifying neighbors: %d/%d hosts processed... (active: %d)", spinner[idx], count, total, len(activeHosts))
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

		// Pad raw status to exactly 8 characters first, then color it Green (\x1b[1;32m) to represent "UP / Active" status consistently
		statusPadded := fmt.Sprintf("%-8s", status)
		statusColored := "\x1b[1;32m" + statusPadded + "\x1b[0m"

		// Format open ports elegantly with a strict truncation limit of 2 to preserve columns
		portsStr := formatPorts(host.OpenPorts)

		// Create Vane syntax suggestions with matrix-aligned coloring
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		var syntaxColored string
		parts := strings.Split(host.IP, ".")
		if len(parts) == 4 {
			lastOctet := parts[3]
			mod := ">"
			if isLoopback {
				mod = ":"
			}

			suffix := lastOctet
			if !isLoopback && host.IP == gatewayIP {
				suffix = "gw"
			}

			plain := fmt.Sprintf("%s|%s...%s", ifaceName, mod, suffix)
			var coloredMod string
			switch mod {
			case ">":
				coloredMod = "\x1b[1;32m>\x1b[0m" // Green
			case ":":
				coloredMod = "\x1b[1;35m:\x1b[0m" // Magenta
			default:
				coloredMod = mod
			}

			padding := 16 - len(plain)
			if padding < 0 {
				padding = 0
			}
			syntaxColored = fmt.Sprintf("%s|%s...%s%s", ifaceName, coloredMod, suffix, strings.Repeat(" ", padding))
		} else {
			syntaxColored = fmt.Sprintf("%-16s", "──")
		}

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

	fmt.Printf("  Discovered %d active neighbors.\n", len(activeHosts))
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
