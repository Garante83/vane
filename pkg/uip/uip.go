package uip

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"vane/pkg/netstate"
)

// Token represents the parsed components of a Vane-syntax network token.
type Token struct {
	FullMatch string // The entire matched Vane expression (e.g. "eno1|>...gw:80")
	Interface string // The target network interface name (e.g. "eno1")
	Direction string // The direction modifier: '>', '<', ':', or '!'
	Dots      int    // The number of dots indicating segment masking depth
	HostPart  string // The dynamic host part (numeric octet, "gw", or "router")
	Port      string // Optional TCP/UDP port suffix (e.g. "80")
}

// vaneRegex defines the structural pattern of the Vane CLI syntax.
var vaneRegex = regexp.MustCompile(`([a-zA-Z0-9]+)\s*\|([>:<!])(\.+)([a-zA-Z0-9\.:]+)(?::([0-9]+))?`)

// ResolveSemanticHook is a callback function that the caller can register to resolve semantic/service tokens.
// It takes the token and the netstate, and returns the resolved IP, a boolean indicating if it was handled, and any error.
var ResolveSemanticHook func(token *Token, state *netstate.State) (string, bool, error)

// IsSemanticToken returns true if the hostpart represents a semantic service-oriented token
// rather than a numeric IP segment, gateway keyword, or hex MAC suffix.
func IsSemanticToken(hostPart string) bool {
	if hostPart == "gw" || hostPart == "router" {
		return false
	}
	// If it contains any character that is not a hex digit (0-9, a-f, A-F) or a colon/dot,
	// it must be a semantic token.
	for _, c := range hostPart {
		isHexChar := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.'
		if !isHexChar {
			return true
		}
	}
	return false
}

// ParseToken validates and parses a token string (maintained for backwards compatibility).
func ParseToken(input string) (*Token, bool) {
	return ExtractToken(input)
}

// ExtractToken scans the input string and extracts the first valid Vane-syntax token.
func ExtractToken(input string) (*Token, bool) {
	matches := vaneRegex.FindStringSubmatch(input)
	if len(matches) == 0 {
		return nil, false
	}

	hostPart := matches[4]
	port := matches[5]

	// Greedy Regex Correction: If the port group is empty, check if the greedy HostPart matching group
	// consumed the trailing ':port' (e.g. "33:2222" or "3e:8e:2222").
	if port == "" {
		if idx := strings.LastIndex(hostPart, ":"); idx != -1 {
			portCandidate := hostPart[idx+1:]
			isPort := true
			for _, c := range portCandidate {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}
			if isPort && len(portCandidate) > 0 && idx > 0 {
				hostPart = hostPart[:idx]
				port = portCandidate
			}
		}
	}

	return &Token{
		FullMatch: matches[0],
		Interface: strings.TrimSpace(matches[1]),
		Direction: matches[2],
		Dots:      len(matches[3]),
		HostPart:  hostPart,
		Port:      port,
	}, true
}

// ResolveTokenIP is the centralized engine for converting a Vane notation token into a raw IP address
func ResolveTokenIP(targetToken *Token, state *netstate.State) (string, error) {
	// If a semantic hook is registered or this is a semantic token, try resolving it first.
	if ResolveSemanticHook != nil || IsSemanticToken(targetToken.HostPart) {
		if ResolveSemanticHook != nil {
			ip, handled, err := ResolveSemanticHook(targetToken, state)
			if handled {
				if err != nil {
					return "", err
				}
				return ip, nil
			}
		}
		if IsSemanticToken(targetToken.HostPart) {
			return "", fmt.Errorf("[vane] Error: Semantisches Token '%s' konnte nicht aufgelöst werden (kein aktiver Service-Finder oder Cache vorhanden)", targetToken.HostPart)
		}
	}

	var targetIP string

	switch targetToken.Direction {
	case ">": // Outbound LAN (Dual-Stack: IPv6 ULA first, fallback to IPv4)
		useIPv6 := false
		if state.IPv6ULA != nil {
			useIPv6 = true
		}

		if useIPv6 {
			// Resolve using IPv6 ULA
			if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
				gw, err := GetIPv6DefaultGateway(state.InterfaceName)
				if err == nil && gw != "" {
					targetIP = gw
				} else {
					// Fallback to IPv4 gateway if IPv6 gateway isn't found
					if state.IPv4Local != nil {
						gwV4, errV4 := GetDefaultGateway(state.InterfaceName)
						if errV4 == nil && gwV4 != "" {
							targetIP = gwV4
						} else {
							return "", fmt.Errorf("[vane] Error: Standard-Gateway für Interface %s konnte nicht ermittelt werden: %v", state.InterfaceName, err)
						}
					} else {
						return "", fmt.Errorf("[vane] Error: Standard-Gateway für Interface %s konnte nicht ermittelt werden: %v", state.InterfaceName, err)
					}
				}
			} else {
				targetIP = ResolveIPv6ULA(state.IPv6ULA, targetToken.HostPart)
			}
		} else {
			// Fallback to IPv4
			if state.IPv4Local == nil {
				// Final extreme fallback: if IPv6 GUA is active, try it as a last resort
				if state.IPv6Global != nil {
					if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
						gw, err := GetIPv6DefaultGateway(state.InterfaceName)
						if err == nil && gw != "" {
							return gw, nil
						}
					}
					return ResolveIPv6ULA(state.IPv6Global, targetToken.HostPart), nil
				}
				return "", fmt.Errorf("[vane] Error: Keine valide IPv4-Adresse auf Interface %s", targetToken.Interface)
			}

			// Passive APIPA validation check to catch DHCP lease errors early
			if state.IsAPIPA {
				return "", fmt.Errorf("[!] vane ─ APIPA erkannt auf %s (DHCP-FAIL)", targetToken.Interface)
			}

			// Dynamic gateway resolution for 'gw' or 'router' keywords
			if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
				gw, err := GetDefaultGateway(state.InterfaceName)
				if err != nil {
					return "", fmt.Errorf("[vane] Error: Standard-Gateway für Interface %s konnte nicht ermittelt werden: %v", state.InterfaceName, err)
				}
				targetIP = gw
			} else {
				// Check if HostPart is a MAC suffix
				isHex := false
				for _, c := range targetToken.HostPart {
					if (c < '0' || c > '9') && c != '.' {
						isHex = true
						break
					}
				}
				if len(targetToken.HostPart) >= 4 && !strings.Contains(targetToken.HostPart, ".") {
					isHex = true
				}
				if !isHex && !strings.Contains(targetToken.HostPart, ".") {
					if num, err := strconv.Atoi(targetToken.HostPart); err == nil && num > 255 {
						isHex = true
					}
				}

				if isHex {
					eui64 := ""
					if len(state.HardwareAddr) == 6 {
						eui64 = ComputeEUI64(state.HardwareAddr)
					}
					valClean := strings.ToLower(strings.ReplaceAll(targetToken.HostPart, ":", ""))
					euiClean := strings.ToLower(strings.ReplaceAll(eui64, ":", ""))

					matched := false
					if euiClean != "" && valClean != "" {
						if strings.HasSuffix(euiClean, valClean) || strings.Contains(euiClean, valClean) {
							matched = true
						}
					}

					if matched {
						targetIP = state.IPv4Local.String()
					} else {
						resolvedIP, err := ResolveRemoteIPFromARP(state.InterfaceName, targetToken.HostPart)
						if err == nil && resolvedIP != "" {
							targetIP = resolvedIP
						} else {
							return "", fmt.Errorf("[vane] Error: MAC-Suffix '%s' stimmt nicht mit Interface %s überein", targetToken.HostPart, state.InterfaceName)
						}
					}
				} else {
					targetIP = ResolveIPv4Dots(state.IPv4Local, targetToken.Dots, targetToken.HostPart)
				}
			}
		}

	case "<": // External WAN (IPv6)
		if state.IPv6Global == nil {
			return "", fmt.Errorf("[vane] Error: Keine globale IPv6-Adresse (GUA) auf Interface %s", targetToken.Interface)
		}
		targetIP = ResolveIPv6WAN(state.IPv6Global, targetToken.HostPart, state.HardwareAddr)

	case ":": // Loopback (lo)
		if targetToken.HostPart == "1" {
			targetIP = "::1"
		} else {
			baseIP := net.ParseIP("127.0.0.1")
			if state.IPv4Local != nil {
				baseIP = state.IPv4Local
			}
			targetIP = ResolveIPv4Dots(baseIP, targetToken.Dots, targetToken.HostPart)
		}

	case "!": // APIPA (DHCP-FAIL fallback)
		if state.IPv4Local != nil && state.IsAPIPA {
			targetIP = ResolveIPv4Dots(state.IPv4Local, targetToken.Dots, targetToken.HostPart)
		} else {
			parts := []string{"169", "254", "0", targetToken.HostPart}
			targetIP = strings.Join(parts, ".")

			// Proactive Admin Helper: Warn that local interface is NOT on APIPA!
			fmt.Fprintf(os.Stderr, "\n[!] Warning: Target resolves to APIPA IP (%s), but interface %s has no active APIPA lease.\n", targetIP, state.InterfaceName)
			fmt.Fprintf(os.Stderr, "[!] To enable communication on this segment, run:\n")
			if runtime.GOOS == "windows" {
				fmt.Fprintf(os.Stderr, "    New-NetIPAddress -InterfaceAlias '%s' -IPAddress 169.254.99.99 -PrefixLength 16\n\n", state.InterfaceName)
			} else {
				fmt.Fprintf(os.Stderr, "    sudo ip addr add 169.254.99.99/16 dev %s\n\n", state.InterfaceName)
			}
		}

	default:
		return "", fmt.Errorf("[vane] Error: Unbekannter Richtungs-Modifikator '%s'", targetToken.Direction)
	}

	return targetIP, nil
}

// ResolveIPv4Dots formats the local IPv4 address by overriding octets relative to the dot count
func ResolveIPv4Dots(localIP net.IP, dotCount int, hostPart string) string {
	parts := strings.Split(localIP.String(), ".")
	if dotCount > 0 && dotCount <= len(parts) {
		return strings.Join(parts[:dotCount], ".") + "." + hostPart
	}
	return hostPart
}

// ResolveIPv6WAN resolves a global unicast WAN IPv6 address using EUI-64 or hybrid injection
func ResolveIPv6WAN(globalIP net.IP, hostPart string, mac net.HardwareAddr) string {
	if hostPart == "0" || hostPart == "" {
		eui64 := ComputeEUI64(mac)
		if eui64 != "" {
			prefixStr := GetPrefix64(globalIP, "2000::")
			return prefixStr + ":" + eui64
		}
	}

	prefix := globalIP.Mask(net.CIDRMask(64, 128))
	num, _ := strconv.Atoi(hostPart)

	prefix[14] = byte(num >> 8)
	prefix[15] = byte(num)

	return prefix.String()
}

// ComputeEUI64 calculates the standard 64-bit EUI-64 identifier from a 6-byte hardware MAC
func ComputeEUI64(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	b0 := mac[0] ^ 0x02
	return fmt.Sprintf("%02x%02x:%02xff:fe%02x:%02x%02x", b0, mac[1], mac[2], mac[3], mac[4], mac[5])
}

// GetPrefix64 extracts the /64 routing prefix of an IPv6 address
func GetPrefix64(ip net.IP, fallback string) string {
	if ip == nil {
		return fallback
	}
	prefix := ip.Mask(net.CIDRMask(64, 128))
	parts := strings.Split(prefix.String(), ":")
	if len(parts) >= 4 {
		return strings.Join(parts[:4], ":") + ":"
	}
	return fallback
}

// ResolveIPv6ULA replaces the final hex segment group of an IPv6 Unique Local Address
func ResolveIPv6ULA(ula net.IP, hostPart string) string {
	ipBytes := ula.To16()
	if ipBytes == nil {
		return ula.String()
	}

	cleanHex := strings.ReplaceAll(hostPart, ":", "")
	val, err := strconv.ParseUint(cleanHex, 16, 64)
	if err == nil {
		if len(cleanHex) <= 4 {
			ipBytes[14] = byte(val >> 8)
			ipBytes[15] = byte(val)
		} else {
			ipBytes[12] = byte(val >> 24)
			ipBytes[13] = byte(val >> 16)
			ipBytes[14] = byte(val >> 8)
			ipBytes[15] = byte(val)
		}
		return net.IP(ipBytes).String()
	}
	return ula.String()
}

// ResolveRemoteIPFromARP reads the dynamic system ARP table cache to map MAC hex suffixes to local subnet IPs
func ResolveRemoteIPFromARP(ifaceName, suffix string) (string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetNeighbor -InterfaceAlias '%s' | Select-Object IPAddress, LinkLayerAddress", ifaceName))
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ip := fields[0]
					mac := strings.ToLower(strings.ReplaceAll(fields[1], "-", ""))
					cleanSuffix := strings.ToLower(strings.ReplaceAll(suffix, ":", ""))
					if strings.HasSuffix(mac, cleanSuffix) || strings.Contains(mac, cleanSuffix) {
						return ip, nil
					}
				}
			}
		}
		return "", fmt.Errorf("MAC suffix not found in Windows ARP neighbor cache")
	}

	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "", err
	}

	cleanSuffix := strings.ToLower(strings.ReplaceAll(suffix, ":", ""))
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
		mac := strings.ToLower(strings.ReplaceAll(fields[3], ":", ""))
		dev := fields[5]

		if dev == ifaceName {
			if strings.HasSuffix(mac, cleanSuffix) || strings.Contains(mac, cleanSuffix) {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("MAC suffix '%s' not found in ARP cache for %s", suffix, ifaceName)
}

// GetDefaultGateway retrieves the active IPv4 default gateway for a local interface
func GetDefaultGateway(ifaceName string) (string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetRoute -InterfaceAlias '%s' -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop", ifaceName))
		out, err := cmd.Output()
		if err != nil || len(strings.TrimSpace(string(out))) == 0 {
			return "", fmt.Errorf("no default gateway found for interface %s", ifaceName)
		}
		ip := strings.TrimSpace(string(out))
		if ip == "" || ip == "0.0.0.0" {
			return "", fmt.Errorf("no default gateway configured")
		}
		return ip, nil
	}

	data, err := os.ReadFile("/proc/net/route")
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
		iface := fields[0]
		dest := fields[1]
		gwHex := fields[2]

		if iface == ifaceName && dest == "00000000" {
			if gwHex == "00000000" {
				continue
			}
			ip, err := parseGatewayHex(gwHex)
			if err == nil {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no default gateway found for interface %s", ifaceName)
}

// parseGatewayHex converts little-endian hex routing entries into decimal IPv4 notation
func parseGatewayHex(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("invalid gateway hex format")
	}
	var ipBytes [4]byte
	for i := 0; i < 4; i++ {
		start := 6 - i*2
		val, err := strconv.ParseUint(hexStr[start:start+2], 16, 8)
		if err != nil {
			return "", err
		}
		ipBytes[i] = byte(val)
	}
	return fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]), nil
}

// GetIPv6DefaultGateway retrieves the active IPv6 default gateway for an interface
func GetIPv6DefaultGateway(ifaceName string) (string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetRoute -InterfaceAlias '%s' -AddressFamily IPv6 -DestinationPrefix '::/0' | Select-Object -ExpandProperty NextHop", ifaceName))
		out, err := cmd.Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return strings.TrimSpace(string(out)), nil
		}
		return "", fmt.Errorf("no ipv6 default gateway found on %s", ifaceName)
	}

	data, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		destHex := fields[0]
		gwHex := fields[4]
		dev := fields[9]

		if dev == ifaceName && destHex == "00000000000000000000000000000000" {
			if gwHex == "00000000000000000000000000000000" {
				continue
			}
			ip, err := parseIPv6Hex(gwHex)
			if err == nil {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("no ipv6 default route found on %s", ifaceName)
}

// parseIPv6Hex converts standard 32-character hexadecimal IPv6 routing entries into colon-separated notation
func parseIPv6Hex(hexStr string) (string, error) {
	if len(hexStr) != 32 {
		return "", fmt.Errorf("invalid ipv6 hex length")
	}
	var parts []string
	for i := 0; i < 32; i += 4 {
		part := hexStr[i : i+4]
		trimmed := strings.TrimLeft(part, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		parts = append(parts, trimmed)
	}
	ipStr := strings.Join(parts, ":")
	parsedIP := net.ParseIP(ipStr)
	if parsedIP != nil {
		return parsedIP.String(), nil
	}
	return ipStr, nil
}
