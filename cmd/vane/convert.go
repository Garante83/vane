package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"vane/pkg/netstate"
	"vane/pkg/uip"
	"vane/pkg/util"
)

// executeNative launches the target command natively, linking stdin/stdout/stderr streams directly
func executeNative(binary string, args []string) {
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		os.Exit(1)
	}
}

// handleConvert manages the bidirectional network conversion UI (Infocenter)
func handleConvert(ifaceName, val string) {
	state, err := netstate.GetInterfaceState(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}

	// Check if input value is hexadecimal
	isHex := false
	for _, c := range val {
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' {
			isHex = true
			break
		}
	}
	if len(val) >= 4 && !isHex && !strings.Contains(val, ".") {
		isHex = true
	}
	if !isHex && !strings.Contains(val, ".") {
		if num, err := strconv.Atoi(val); err == nil && num > 255 {
			isHex = true
		}
	}

	if isHex {
		eui64 := ""
		if len(state.HardwareAddr) == 6 {
			eui64 = uip.ComputeEUI64(state.HardwareAddr)
		}

		valClean := strings.ToLower(strings.ReplaceAll(val, ":", ""))
		euiClean := strings.ToLower(strings.ReplaceAll(eui64, ":", ""))

		matched := false
		if euiClean != "" && valClean != "" {
			if strings.HasSuffix(euiClean, valClean) || strings.Contains(euiClean, valClean) {
				matched = true
			}
		}

		if matched && state.IPv4Local != nil {
			fmt.Printf(msg.ConvertIPv4Equiv, state.IPv4Local.String())
		} else if state.IPv4Local != nil {
			fmt.Printf(msg.ConvertIPv4Equiv, state.IPv4Local.String())
		} else {
			fmt.Fprintf(os.Stderr, msg.ErrorNoIPConvert, ifaceName)
			os.Exit(1)
		}
		return
	}

	// Fallback conversion to decimal output matrix
	ipv4Str := "192.168.178.53"
	dots := 3
	if state.IPv4Local != nil {
		dots = 4 - strings.Count(val, ".") - 1
		ipv4Str = uip.ResolveIPv4Dots(state.IPv4Local, dots, val)
	}

	eui64 := "1ac0:4dff:feda:3e8e"
	if len(state.HardwareAddr) == 6 {
		eui64 = uip.ComputeEUI64(state.HardwareAddr)
	}

	linkLocal := "fe80::" + eui64
	ulaPrefix := uip.GetPrefix64(state.IPv6ULA, "fd99:9731:b7c6:0:")
	globalPrefix := uip.GetPrefix64(state.IPv6Global, "2002:d5b6:7403:0:")

	if !strings.HasSuffix(ulaPrefix, ":") {
		ulaPrefix += ":"
	}
	if !strings.HasSuffix(globalPrefix, ":") {
		globalPrefix += ":"
	}

	dotsStr := strings.Repeat(".", dots)
	if dots < 0 {
		dotsStr = ""
	}
	fmt.Printf("-> Vane-Syntax:   %s|>%s%s\n", ifaceName, dotsStr, val)
	fmt.Printf("-> IPv4-Standard: %s\n", ipv4Str)
	fmt.Printf("-> Link-Local:    %s\n", linkLocal)
	fmt.Printf(msg.ConvertULA, ulaPrefix, eui64)
	fmt.Printf("-> Global (WAN):  %s%s\n", globalPrefix, eui64)
}

// printInterfaceMatrix outputs the beautifully formatted local network interface report
func printInterfaceMatrix() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}

	truncateStr := util.TruncateStr

	fmt.Println("┌──────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│  vane ─ Local Network Interface Matrix                                       │")
	fmt.Println("└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Println("  INTERFACE                 STATUS    TYPE       VANE-SYNTAX        REAL IP / DESIGNATION     ")
	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")

	activeCount := 0
	for _, iface := range ifaces {
		state, err := netstate.GetInterfaceState(iface.Name)
		if err != nil {
			continue
		}

		isUp := (iface.Flags & net.FlagUp) != 0
		coloredStatus := getColoredStatus(isUp)

		typeStr := "LAN"
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		isWlan := strings.Contains(strings.ToLower(iface.Name), "wlan") || strings.Contains(strings.ToLower(iface.Name), "wi-fi")
		if state.IsAPIPA {
			typeStr = "APIPA"
		} else if isLoopback {
			typeStr = "Loopback"
		} else if isWlan {
			typeStr = "WLAN"
		}

		// Calculate index-based interface representation matching Vane's internal parser
		displayName := iface.Name
		if isLoopback {
			displayName = fmt.Sprintf("[0] %s", iface.Name)
		} else if !isLoopback && isUp {
			activeCount++
			displayName = fmt.Sprintf("[%d] %s", activeCount, iface.Name)
		}
		displayName = truncateStr(displayName, 25)

		if isLoopback {
			v4Str := "127.0.0.1"
			if state.IPv4Local != nil {
				v4Str = state.IPv4Local.String()
			}
			v6Str := "::1"
			if state.IPv6LinkLocal != nil {
				v6Str = state.IPv6LinkLocal.String()
			}
			coloredSyntax := getColoredSyntax(iface.Name, ":", "1")
			fmt.Printf("  %-25s %s %-10s %s %s / %s\n", displayName, coloredStatus, typeStr, coloredSyntax, v4Str, v6Str)
		} else if !isUp {
			fmt.Printf("  %-25s %s %-10s %s [No Carrier]\n", displayName, coloredStatus, typeStr, getColoredSyntax("───", "", ""))
		} else if state.IsAPIPA {
			lastOctet := "34"
			if state.IPv4Local != nil {
				parts := strings.Split(state.IPv4Local.String(), ".")
				if len(parts) == 4 {
					lastOctet = parts[3]
				}
			}
			ipStr := "169.254.12.34"
			if state.IPv4Local != nil {
				ipStr = state.IPv4Local.String()
			}
			coloredSyntax := getColoredSyntax(iface.Name, "!", lastOctet)
			fmt.Printf("  %-25s %s %-10s %s %s (DHCP-FAIL)\n", displayName, coloredStatus, typeStr, coloredSyntax, ipStr)
		} else {
			hasV4 := state.IPv4Local != nil
			hasV6 := state.IPv6Global != nil

			if hasV4 {
				lastOctet := "53"
				parts := strings.Split(state.IPv4Local.String(), ".")
				if len(parts) == 4 {
					lastOctet = parts[3]
				}
				v4Type := typeStr + " (v4)"
				coloredSyntax := getColoredSyntax(iface.Name, ">", lastOctet)
				fmt.Printf("  %-25s %s %-10s %s %s\n", displayName, coloredStatus, v4Type, coloredSyntax, state.IPv4Local.String())

				// Dynamic Default Gateway Line
				gwIP, err := uip.GetDefaultGateway(iface.Name)
				if err == nil && gwIP != "" {
					gwType := "(Gateway)"
					gwSyntax := getColoredSyntax(iface.Name, ">", "gw")
					fmt.Printf("  %-25s %-9s %-10s %s %s\n", "", "", gwType, gwSyntax, gwIP)
				}
			}

			if hasV6 {
				eui64 := ""
				if len(state.HardwareAddr) == 6 {
					eui64 = uip.ComputeEUI64(state.HardwareAddr)
				}
				lastFour := "3e8e"
				if len(eui64) >= 4 {
					lastFour = strings.ReplaceAll(eui64, ":", "")
					if len(lastFour) >= 4 {
						lastFour = lastFour[len(lastFour)-4:]
					}
				}

				prefixStr := uip.GetPrefix64(state.IPv6Global, "2001:9731:")
				displayIP := prefixStr + "...:" + lastFour

				v6Type := typeStr + " (v6)"
				coloredSyntax := getColoredSyntax(iface.Name, "<", lastFour)

				if hasV4 {
					fmt.Printf("  %-25s %-9s %-10s %s %s\n", "", "", v6Type, coloredSyntax, displayIP)
				} else {
					fmt.Printf("  %-25s %s %-10s %s %s\n", displayName, coloredStatus, v6Type, coloredSyntax, displayIP)
				}
			}

			if !hasV4 && !hasV6 {
				fmt.Printf("  %-11s %s %-10s %s %s\n", displayName, coloredStatus, typeStr, getColoredSyntax("───", "", ""), msg.NoIPBound)
			}
		}
	}
	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")
}
