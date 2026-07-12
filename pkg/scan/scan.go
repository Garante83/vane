package scan

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
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

// PerformScan executes a fast parallel targeted check of all hosts in the subnetwork range
func PerformScan(ifaceName string) error {
	// 1. Enforce root privileges on non-Windows systems using secure sudo self-re-execution
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		// Check if sudo requires a password (non-interactive check)
		needsPassword := true
		checkCmd := exec.Command("sudo", "-n", "true")
		if errCheck := checkCmd.Run(); errCheck == nil {
			needsPassword = false
		}

		if needsPassword {
			if getSystemLanguage() == "de" {
				fmt.Println("  \x1b[1;33m[!] root-Rechte für Subnetz-Sweep benötigt. Starte neu mit 'sudo'...\x1b[0m")
			} else {
				fmt.Println("  \x1b[1;33m[!] root privileges required for subnet sweep. Relaunching with 'sudo'...\x1b[0m")
			}
		}

		// Re-execute current binary with sudo
		cmd := exec.Command("sudo", os.Args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("sudo re-execution failed: %w", err)
		}
		os.Exit(0)
	}

	// 2. Locate interface and IP
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

	// 3. Generate all target IPs in the active local subnet CIDR
	subnetIPs := getSubnetIPs(localIP)
	gatewayIP := getGatewayIP(ifaceName)

	// Display scanning header
	fmt.Println("┌──────────────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│  vane scan ─ Neighbor Discovery Matrix (Interface: %-24s) │\n", ifaceName)
	fmt.Println("└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Printf("  Sweeping %d possible IP targets in local subnet %s...\n\n", len(subnetIPs), localIP.String())

	// 4. Parallel targeted checks (Worker Pool)
	commonPorts := []string{"22", "80", "443", "445", "3389", "8080"}
	resultsChan := make(chan ScanResult, len(subnetIPs))
	targetsChan := make(chan string, len(subnetIPs))

	var wg sync.WaitGroup
	numWorkers := 50 // Fast concurrent sweep

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ipStr := range targetsChan {
				// Don't dial ourselves
				if ipStr == localIP.IP.String() {
					resultsChan <- ScanResult{
						IP:        ipStr,
						IsAlive:   true,
						OpenPorts: checkLocalPorts(commonPorts),
						MAC:       iface.HardwareAddr.String(),
					}
					continue
				}

				alive, openPorts := peekHost(ipStr, commonPorts)
				resultsChan <- ScanResult{
					IP:        ipStr,
					IsAlive:   alive,
					OpenPorts: openPorts,
					MAC:       "", // Will be populated from ARP cache after dialing
				}
			}
		}()
	}

	// Feed all subnet IPs to workers
	for _, ip := range subnetIPs {
		targetsChan <- ip
	}
	close(targetsChan)

	// Wait for workers to finish scanning in background
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Gather alive results with progress spinner
	var activeHosts []ScanResult
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	idx := 0
	count := 0
	total := len(subnetIPs)

	for res := range resultsChan {
		count++
		if res.IsAlive {
			activeHosts = append(activeHosts, res)
		}
		idx = (idx + 1) % len(spinner)
		fmt.Printf("\r  %s Sweeping subnet: %d/%d hosts processed... (active: %d)", spinner[idx], count, total, len(activeHosts))
	}

	// Erase the progress line
	fmt.Print("\r\x1b[K")

	// 5. Parse ARP table *AFTER* workers have finished dialing (so OS neighbor cache is populated!)
	arpMap := parseARPTable(ifaceName)

	// Populate MAC addresses from the fresh ARP map
	for i, host := range activeHosts {
		if host.IP == localIP.IP.String() {
			continue
		}
		if mac, exists := arpMap[host.IP]; exists {
			activeHosts[i].MAC = mac
		} else if host.IP == gatewayIP {
			// Try looking up gateway MAC address if gatewayIP was resolved
			if macGw, errGw := lookupMACForGateway(ifaceName, gatewayIP); errGw == nil && macGw != "" {
				activeHosts[i].MAC = macGw
			}
		}
	}

	sort.Slice(activeHosts, func(i, j int) bool {
		ip1 := net.ParseIP(activeHosts[i].IP)
		ip2 := net.ParseIP(activeHosts[j].IP)
		return bytes.Compare(ip1, ip2) < 0
	})

	// 6. Visual Tabular Output
	fmt.Printf("  %-16s %-8s %-16s %-16s %s\n", "IP ADDRESS", "STATUS", "PORT PEEK", "VANE-SYNTAX", "MAC / VENDOR")
	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")

	for _, host := range activeHosts {
		status := "[ UP ]"
		if host.IP == localIP.IP.String() {
			status = "[LOCAL]"
		} else if host.IP == gatewayIP {
			status = "[ GW ]"
		}

		statusPadded := fmt.Sprintf("%-8s", status)
		statusColored := "\x1b[1;32m" + statusPadded + "\x1b[0m"

		portsStr := formatPorts(host.OpenPorts)

		// Create Vane syntax suggestions
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
				coloredMod = "\x1b[1;32m>\x1b[0m"
			case ":":
				coloredMod = "\x1b[1;35m:\x1b[0m"
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

		macVendor := "──"
		if host.MAC != "" {
			vendor := resolveVendor(host.MAC)
			if vendor != "" {
				macVendor = fmt.Sprintf("%s (%s)", host.MAC, vendor)
			} else {
				macVendor = host.MAC
			}
		}

		fmt.Printf("  %-16s %s %-16s %s %s\n", host.IP, statusColored, portsStr, syntaxColored, macVendor)
	}

	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("  Discovered %d active hosts in subnetwork range.\n", len(activeHosts))
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
				_ = conn.Close()
				lock.Lock()
				alive = true
				openPorts = append(openPorts, p)
				lock.Unlock()
			} else {
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
			open = append(open, port)
		} else {
			_ = ln.Close()
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

// lookupMACForGateway resolves the gateway MAC address from ARP table without interface match
func lookupMACForGateway(ifaceName, gatewayIP string) (string, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "", err
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
		ip := fields[0]
		mac := fields[3]
		if ip == gatewayIP && mac != "00:00:00:00:00:00" {
			return mac, nil
		}
	}
	return "", fmt.Errorf("not found")
}

// getSubnetIPs calculates all valid host IPv4 addresses inside a CIDR block
func getSubnetIPs(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	for {
		ip = incrementIP(ip)
		if !ipNet.Contains(ip) {
			break
		}
		// Skip subnet network and broadcast addresses
		if isNetworkOrBroadcastIP(ip, ipNet.Mask) {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips
}

func incrementIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

func isNetworkOrBroadcastIP(ip net.IP, mask net.IPMask) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	lastByte := ip4[3]
	if lastByte == 0 || lastByte == 255 {
		return true
	}
	return false
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
			if len(gwHex) == 8 {
				var ipBytes [4]byte
				for j := 0; j < 4; j++ {
					start := 6 - j*2
					val := 0
					_, _ = fmt.Sscanf(gwHex[start:start+2], "%x", &val)
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
		"bc2411": "Proxmox Server Solutions",
	}

	if name, ok := vendors[oui]; ok {
		return name
	}
	return ""
}

func getSystemLanguage() string {
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
		val := os.Getenv(env)
		if strings.HasPrefix(strings.ToLower(val), "de") {
			return "de"
		}
	}
	return "en"
}
