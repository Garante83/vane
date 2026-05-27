package netstate

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// State represents the gathered network configuration and status of a local network interface.
type State struct {
	InterfaceName string           // Name of the network interface (e.g. "eno1")
	IPv4Local     net.IP           // Active local IPv4 address
	IPv6Global    net.IP           // Active global unicast IPv6 address (GUA)
	IPv6ULA       net.IP           // Unique Local IPv6 Address (ULA)
	IPv6LinkLocal net.IP           // Link-local IPv6 address (fe80::)
	HardwareAddr  net.HardwareAddr // MAC address of the interface
	IsAPIPA       bool             // True if APIPA (169.254.x.x) is detected (indicating DHCP failure)
}

// GetInterfaceState dynamically scans the specified interface directly via kernel APIs.
func GetInterfaceState(ifaceName string) (*State, error) {
	iface, err := findInterface(ifaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to read addresses from %s: %w", iface.Name, err)
	}

	state := &State{
		InterfaceName: iface.Name,
		HardwareAddr:  iface.HardwareAddr,
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP

		// 1. Process IPv4 addresses & detect APIPA link-local fail states
		if ip.To4() != nil {
			// Check for APIPA range: 169.254.0.0/16
			if ip[12] == 169 && ip[13] == 254 {
				state.IsAPIPA = true
				state.IPv4Local = ip
			} else if !ip.IsLoopback() {
				state.IPv4Local = ip
			}
			continue
		}

		// 2. Process IPv6 addresses (differentiate between GUA, ULA, and Link-Local)
		if ip.To4() == nil {
			if ip.IsLinkLocalUnicast() {
				state.IPv6LinkLocal = ip
			} else if ip.IsGlobalUnicast() {
				if strings.HasPrefix(ip.String(), "fd") || strings.HasPrefix(ip.String(), "fc") {
					state.IPv6ULA = ip
				} else {
					state.IPv6Global = ip
				}
			}
		}
	}

	return state, nil
}

// findInterface locates a local network interface by its name, system index, or alias.
// This abstract method ensures seamless operation across Linux, macOS, and Windows.
func findInterface(name string) (*net.Interface, error) {
	// Attempt direct lookup by exact name
	if iface, err := net.InterfaceByName(name); err == nil {
		return iface, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	isActive := func(i net.Interface) bool {
		return (i.Flags & net.FlagUp) != 0
	}

	// 1. Index-based matching: "0" matches loopback, "1" matches the first active physical adapter
	if idx, err := strconv.Atoi(name); err == nil {
		if idx == 0 {
			// Find and return the loopback interface
			for _, i := range ifaces {
				if (i.Flags & net.FlagLoopback) != 0 {
					return &i, nil
				}
			}
		}

		activeCount := 0
		for _, i := range ifaces {
			if (i.Flags & net.FlagLoopback) != 0 {
				continue
			}
			if isActive(i) {
				activeCount++
				if activeCount == idx {
					return &i, nil
				}
			}
		}
	}

	// 2. Alias mapping: maps common abbreviations (e.g. eth0, wlan0) to OS names (e.g. Ethernet, Wi-Fi)
	nameLower := strings.ToLower(name)
	var targetSub string
	targetIndex := 1

	aliasBase := nameLower
	for i := len(nameLower) - 1; i >= 0; i-- {
		if nameLower[i] >= '0' && nameLower[i] <= '9' {
			continue
		}
		if i < len(nameLower)-1 {
			aliasBase = nameLower[:i+1]
			idxStr := nameLower[i+1:]
			if val, err := strconv.Atoi(idxStr); err == nil {
				targetIndex = val
			}
		}
		break
	}

	if strings.HasPrefix(aliasBase, "eth") {
		targetSub = "ethernet"
	} else if strings.HasPrefix(aliasBase, "wlan") || strings.HasPrefix(aliasBase, "wifi") {
		targetSub = "wi-fi"
	}

	if targetSub != "" {
		matchCount := 0
		for _, i := range ifaces {
			iNameLower := strings.ToLower(i.Name)
			if strings.Contains(iNameLower, targetSub) || (targetSub == "wi-fi" && strings.Contains(iNameLower, "wlan")) {
				matchCount++
				if matchCount == targetIndex {
					return &i, nil
				}
			}
		}
	}

	// Fallback: Case-insensitive prefix matching
	for _, i := range ifaces {
		if strings.HasPrefix(strings.ToLower(i.Name), nameLower) {
			return &i, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}
