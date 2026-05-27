package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"vane/pkg/netstate"
)

// getSystemLanguage detects the system locale via environment variables or PowerShell
func getSystemLanguage() string {
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
		val := os.Getenv(env)
		if val != "" {
			valLower := strings.ToLower(val)
			if strings.HasPrefix(valLower, "de") {
				return "de"
			}
			if strings.HasPrefix(valLower, "en") {
				return "en"
			}
		}
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "[System.Globalization.CultureInfo]::CurrentCulture.TwoLetterISOLanguageName")
		out, err := cmd.Output()
		if err == nil {
			lang := strings.TrimSpace(strings.ToLower(string(out)))
			if lang == "de" {
				return "de"
			}
		}
	}

	return "en"
}

// getDefaultActiveInterface detects the first active, non-loopback network interface with a valid IPv4 address
func getDefaultActiveInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagLoopback) != 0 {
			continue
		}
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		state, err := netstate.GetInterfaceState(iface.Name)
		if err == nil && state.IPv4Local != nil && !state.IsAPIPA {
			return iface.Name
		}
	}
	return ""
}

// extractPortFromFlags scans CLI arguments for standard TCP/UDP port flags (-p, -P, --port)
func extractPortFromFlags(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		arg := args[i]
		if arg == "-p" || arg == "-P" || arg == "--port" {
			next := args[i+1]
			if _, err := strconv.Atoi(next); err == nil {
				return next
			}
		}
	}
	return ""
}

// getColoredStatus pads status indicators and injects visual high-contrast ANSI status colors
func getColoredStatus(isUp bool) string {
	plain := "[DOWN]"
	if isUp {
		plain = "[ UP ]"
	}
	padded := fmt.Sprintf("%-9s", plain)
	if isUp {
		return strings.Replace(padded, "[ UP ]", "\x1b[1;32m[ UP ]\x1b[0m", 1)
	}
	return strings.Replace(padded, "[DOWN]", "\x1b[1;31m[DOWN]\x1b[0m", 1)
}

// getColoredSyntax pads and applies rich ANSI coloring to syntax direction modifiers
func getColoredSyntax(ifaceName, mod, suffix string) string {
	if mod == "" {
		return fmt.Sprintf("%-18s", ifaceName)
	}
	plain := fmt.Sprintf("%-5s|%s...%s", ifaceName, mod, suffix)
	padded := fmt.Sprintf("%-18s", plain)

	var coloredMod string
	switch mod {
	case ">":
		coloredMod = "\x1b[1;32m>\x1b[0m" // Green for Outbound LAN
	case "<":
		coloredMod = "\x1b[1;36m<\x1b[0m" // Cyan for External WAN
	case ":":
		coloredMod = "\x1b[1;35m:\x1b[0m" // Magenta for Loopback
	case "!":
		coloredMod = "\x1b[1;33m!\x1b[0m" // Yellow warning alarm for APIPA
	default:
		coloredMod = mod
	}
	return strings.Replace(padded, "|"+mod, "|"+coloredMod, 1)
}
