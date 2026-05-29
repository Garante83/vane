package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vane/pkg/doc"
	"vane/pkg/netstate"
	"vane/pkg/peeker"
	"vane/pkg/scan"
	"vane/pkg/sniff"
	"vane/pkg/trace"
	"vane/pkg/transfer"
	"vane/pkg/uip"
	"vane/pkg/vssd"
)

func main() {
	// Register the VSSD semantic resolution hook to resolve dynamic service-oriented tokens.
	// By default (active = false), this runs completely silently via cache or standard mDNS lookup,
	// without creating any files on disk or triggering port sweeps.
	uip.ResolveSemanticHook = func(token *uip.Token, state *netstate.State) (string, bool, error) {
		ip, err := vssd.DiscoverService(state.InterfaceName, token.HostPart, false)
		if err == nil {
			return ip, true, nil
		}
		if uip.IsSemanticToken(token.HostPart) {
			return "", true, err
		}
		return "", false, nil
	}

	// Dynamically detect system language for internationalization.
	// If German is detected, switch to German translations.
	if getSystemLanguage() == "de" {
		msg = de
	}

	// 1. Matrix Report: If no arguments are passed, print the network interface matrix
	if len(os.Args) == 1 {
		printInterfaceMatrix()
		os.Exit(0)
	}

	// 1.5 Intercept autocomplete requests from the shell or for installation
	if len(os.Args) >= 2 && os.Args[1] == "autocomplete" {
		if len(os.Args) >= 3 && os.Args[2] == "--complete" {
			handleAutocomplete(os.Args[3:])
			os.Exit(0)
		}

		// Print installer instructions and the completion script!
		if len(os.Args) >= 3 && (os.Args[2] == "install" || os.Args[2] == "script") {
			printCompletionScript()
			os.Exit(0)
		}

		printAutocompleteHelp()
		os.Exit(0)
	}

	// Simple list flag: Used by the shell autocomplete script to query interface names
	if len(os.Args) == 2 && os.Args[1] == "--list-interfaces-simple" {
		ifaces, err := net.Interfaces()
		if err == nil {
			var names []string
			for _, iface := range ifaces {
				names = append(names, iface.Name)
			}
			fmt.Println(strings.Join(names, " "))
		}
		os.Exit(0)
	}

	// Help screen
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		fmt.Println(msg.HelpTitle)
		fmt.Println(msg.HelpUsageHeader)
		fmt.Println(msg.HelpExecCommand)
		fmt.Println(msg.HelpConvert)
		fmt.Println(msg.HelpScan)
		fmt.Println(msg.HelpTrace)
		fmt.Println(msg.HelpSend)
		fmt.Println(msg.HelpRecv)
		fmt.Println(msg.HelpSniff)
		fmt.Println(msg.HelpDiscover)
		fmt.Println(msg.HelpManual)
		fmt.Println(msg.HelpMatrix)
		os.Exit(0)
	}

	// 1.5 Interactive Manual Mode (vane doc / man / --manual / -m)
	if len(os.Args) == 2 && (os.Args[1] == "doc" || os.Args[1] == "man" || os.Args[1] == "-m" || os.Args[1] == "--manual") {
		doc.ShowManual(getSystemLanguage())
		os.Exit(0)
	}

	// 2. Infocenter Mode: Handle bidirectional network token conversion (-c / --convert)
	if os.Args[1] == "-c" || os.Args[1] == "--convert" {
		if len(os.Args) < 4 {
			fmt.Fprint(os.Stderr, msg.ErrorTooFewArgs)
			fmt.Fprint(os.Stderr, msg.UsageConvert)
			os.Exit(1)
		}
		handleConvert(os.Args[2], os.Args[3])
		os.Exit(0)
	}

	// 2.5 Subcommand: Scan (vane scan [interface])
	if os.Args[1] == "scan" {
		ifaceName := ""
		if len(os.Args) >= 3 {
			ifaceName = os.Args[2]
			// Ultra-resilient UX: If the user accidentally passed a full Vane token (like "eno1|>...33"), extract the interface!
			if t, isVane := uip.ExtractToken(ifaceName); isVane {
				ifaceName = t.Interface
			}
		} else {
			ifaceName = getDefaultActiveInterface()
		}
		if ifaceName == "" {
			fmt.Fprintln(os.Stderr, "[vane] Error: No active network interface with a valid IPv4 address found to scan.")
			os.Exit(1)
		}

		// Resolve alias/index to real name if passed
		state, err := netstate.GetInterfaceState(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}

		err = scan.PerformScan(state.InterfaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.6 Subcommand: Trace (vane trace <target>)
	if os.Args[1] == "trace" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "[vane] Error: Target host expected for trace (e.g. vane trace google.com)")
			os.Exit(1)
		}
		target := os.Args[2]

		// Ultra-resilient UX: If the user passed a Vane token, resolve it to its raw target IP first!
		if t, isVane := uip.ExtractToken(target); isVane {
			state, err := netstate.GetInterfaceState(t.Interface)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
				os.Exit(1)
			}
			resolved, errResolve := uip.ResolveTokenIP(t, state)
			if errResolve != nil {
				fmt.Fprintln(os.Stderr, errResolve.Error())
				os.Exit(1)
			}
			target = resolved
		}

		err := trace.PerformTrace(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.7 Subcommand: Send (vane send <datei> --code <code>)
	if os.Args[1] == "send" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "[vane] Error: File path expected to send (e.g. vane send backup.tar.gz)")
			os.Exit(1)
		}
		filePath := os.Args[2]

		code := ""
		for i := 3; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--code" || os.Args[i] == "-c" {
				code = os.Args[i+1]
				break
			}
		}

		if code == "" {
			fmt.Fprintln(os.Stderr, "[vane] Error: One-time pairing code expected (e.g. vane send backup.tar.gz --code 7392-1845)")
			os.Exit(1)
		}

		err := transfer.PerformSend(filePath, code)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.8 Subcommand: Recv (vane recv [--port <port>])
	if os.Args[1] == "recv" {
		port := "8484"
		for i := 2; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--port" || os.Args[i] == "-p" {
				port = os.Args[i+1]
				break
			}
		}

		err := transfer.PerformReceive(port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.9 Subcommand: Sniff (vane sniff [interface])
	if os.Args[1] == "sniff" {
		ifaceName := ""
		if len(os.Args) >= 3 {
			ifaceName = os.Args[2]
			if t, isVane := uip.ExtractToken(ifaceName); isVane {
				ifaceName = t.Interface
			}
		} else {
			ifaceName = getDefaultActiveInterface()
		}

		if ifaceName == "" && runtime.GOOS == "linux" {
			fmt.Fprintln(os.Stderr, "[vane] Error: No active network interface with a valid IPv4 address found to sniff.")
			os.Exit(1)
		}

		err := sniff.PerformSniff(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.95 Subcommand: Discover (vane discover [interface] [--persistent] [--sweep] [--specific IP] [--clear] [--edit])
	if os.Args[1] == "discover" {
		ifaceName := ""
		persistent := false
		sweepFlag := false
		clearFlag := false
		editFlag := false

		// Parse options
		targetSpec := ""
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			if arg == "--persistent" || arg == "-p" {
				persistent = true
			} else if arg == "--sweep" || arg == "-w" {
				sweepFlag = true
			} else if arg == "--specific" || arg == "-s" {
				if i+1 < len(os.Args) {
					targetSpec = os.Args[i+1]
					i++
				}
			} else if arg == "--clear" || arg == "-c" {
				clearFlag = true
			} else if arg == "--edit" || arg == "-e" {
				editFlag = true
			} else if !strings.HasPrefix(arg, "-") {
				if strings.Contains(arg, "|>") || strings.Contains(arg, "...") || net.ParseIP(arg) != nil {
					targetSpec = arg
				} else if ifaceName == "" {
					ifaceName = arg
				} else {
					targetSpec = arg
				}
			}
		}

		if targetSpec != "" {
			_, isVane := uip.ExtractToken(targetSpec)
			isIP := net.ParseIP(targetSpec) != nil
			if !isVane && !isIP {
				if getSystemLanguage() == "de" {
					fmt.Fprintf(os.Stderr, "[vane] Fehler: Ungültiges Scan-Ziel '%s'. Das Ziel muss eine valide IP-Adresse oder die strikte Vane-Notation sein (z.B. '1|>...pve' oder 'eno1|>...pve').\n", targetSpec)
				} else {
					fmt.Fprintf(os.Stderr, "[vane] Error: Invalid scan target '%s'. Target must be a valid IP address or a strict Vane notation (e.g. '1|>...pve' or 'eno1|>...pve').\n", targetSpec)
				}
				os.Exit(1)
			}

			if t, isVane := uip.ExtractToken(targetSpec); isVane {
				if ifaceName == "" {
					ifaceName = t.Interface
				}
			}
		}

		if ifaceName == "" {
			ifaceName = getDefaultActiveInterface()
		}
		if ifaceName == "" {
			ifaceName = "eno1" // absolute fallback
		}

		// Resolve alias/index to real name if passed (e.g. "1" -> "eno1")
		// Clean full token notation if passed
		if t, isVane := uip.ExtractToken(ifaceName); isVane {
			ifaceName = t.Interface
		}

		var targetIP, targetMAC string
		if targetSpec != "" {
			if net.ParseIP(targetSpec) != nil {
				targetIP = targetSpec
			} else if t, isVane := uip.ExtractToken(targetSpec); isVane {
				state, err := netstate.GetInterfaceState(t.Interface)
				if err == nil {
					resolved, errResolve := uip.ResolveTokenIP(t, state)
					if errResolve == nil {
						targetIP = resolved
					}
				}
			}
		}

		// Handle editor and clear actions immediately (independent of active interface state)
		if clearFlag || editFlag {
			err := handleDiscoverSubcommand(ifaceName, persistent, sweepFlag, clearFlag, editFlag, targetIP, targetMAC)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}

		if ifaceName == "" && runtime.GOOS == "linux" {
			fmt.Fprintln(os.Stderr, "[vane] Error: No active network interface with a valid IPv4 address found for discovery.")
			os.Exit(1)
		}

		state, err := netstate.GetInterfaceState(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}

		err = handleDiscoverSubcommand(state.InterfaceName, persistent, sweepFlag, clearFlag, editFlag, targetIP, targetMAC)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	nativeCmd := os.Args[1]

	// 3. Scan arguments to find the first Vane-syntax token
	var targetToken *uip.Token
	var tokenArgIndex = -1

	for i := 2; i < len(os.Args); i++ {
		t, isVane := uip.ExtractToken(os.Args[i])
		if isVane {
			targetToken = t
			tokenArgIndex = i
			break
		}
	}

	// If no Vane notation is found, transparently pass through to execute natively
	if targetToken == nil {
		executeNative(nativeCmd, os.Args[2:])
		return
	}

	// 4. Query local interface configuration state via netstate package
	state, err := netstate.GetInterfaceState(targetToken.Interface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}

	targetIP, errResolve := uip.ResolveTokenIP(targetToken, state)
	if errResolve != nil {
		fmt.Fprintln(os.Stderr, errResolve.Error())
		os.Exit(1)
	}

	// 5. Pre-flight Port-Peeking (Fast TCP reachability check)
	port := targetToken.Port
	if port == "" {
		port = extractPortFromFlags(os.Args[2:])
	}

	if port != "" {
		if !peeker.CheckPort(targetIP, port) {
			fmt.Fprintf(os.Stderr, msg.PreFlightFail, port, targetIP)
			os.Exit(1)
		}
	}

	// 6. Rewrite CLI arguments dynamically
	var finalArgs []string

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if i == tokenArgIndex {
			replaced := ""
			isWebCmd := nativeCmd == "curl" || nativeCmd == "wget"

			if targetToken.Port != "" {
				if isWebCmd {
					// Retain inline port inside a web query URL
					replaced = strings.ReplaceAll(arg, targetToken.FullMatch, targetIP+":"+targetToken.Port)
				} else {
					// Strip port from the host part (will be appended separately or dropped)
					replaced = strings.ReplaceAll(arg, targetToken.FullMatch, targetIP)
				}
			} else {
				replaced = strings.ReplaceAll(arg, targetToken.FullMatch, targetIP)
			}
			finalArgs = append(finalArgs, replaced)
		} else {
			finalArgs = append(finalArgs, arg)
		}
	}

	// Automatically append protocol-specific port flags for SSH/SCP
	if targetToken.Port != "" {
		if nativeCmd == "ssh" {
			finalArgs = append(finalArgs, "-p", targetToken.Port)
		} else if nativeCmd == "scp" {
			finalArgs = append(finalArgs, "-P", targetToken.Port)
		}
	}

	// Native system handoff: execution is passed directly to the kernel
	executeNative(nativeCmd, finalArgs)
}

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

	fmt.Println("┌──────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│  vane ─ Local Network Interface Matrix                                       │")
	fmt.Println("└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Println("  INTERFACE   STATUS    TYPE       VANE-SYNTAX        REAL IP / DESIGNATION     ")
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
			fmt.Printf("  %-11s %s %-10s %s %s / %s\n", displayName, coloredStatus, typeStr, coloredSyntax, v4Str, v6Str)
		} else if !isUp {
			fmt.Printf("  %-11s %s %-10s %s [No Carrier]\n", displayName, coloredStatus, typeStr, getColoredSyntax("───", "", ""))
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
			fmt.Printf("  %-11s %s %-10s %s %s (DHCP-FAIL)\n", displayName, coloredStatus, typeStr, coloredSyntax, ipStr)
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
				fmt.Printf("  %-11s %s %-10s %s %s\n", displayName, coloredStatus, v4Type, coloredSyntax, state.IPv4Local.String())

				// Dynamic Default Gateway Line
				gwIP, err := uip.GetDefaultGateway(iface.Name)
				if err == nil && gwIP != "" {
					gwType := "(Gateway)"
					gwSyntax := getColoredSyntax(iface.Name, ">", "gw")
					fmt.Printf("  %-11s %-9s %-10s %s %s\n", "", "", gwType, gwSyntax, gwIP)
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
					fmt.Printf("  %-11s %-9s %-10s %s %s\n", "", "", v6Type, coloredSyntax, displayIP)
				} else {
					fmt.Printf("  %-11s %s %-10s %s %s\n", displayName, coloredStatus, v6Type, coloredSyntax, displayIP)
				}
			}

			if !hasV4 && !hasV6 {
				fmt.Printf("  %-11s %s %-10s %s %s\n", displayName, coloredStatus, typeStr, getColoredSyntax("───", "", ""), msg.NoIPBound)
			}
		}
	}
	fmt.Println(" ──────────────────────────────────────────────────────────────────────────────")
}

func getSpelledOutName(token string) string {
	switch token {
	case "pve":
		return "Proxmox VE"
	case "nas":
		return "Nextcloud/NAS"
	case "pi":
		return "Raspberry Pi"
	case "hass":
		return "Home Assistant"
	default:
		return token
	}
}

func getSpelledOutNameCustom(token string, entry vssd.CacheEntry) string {
	if entry.Name != "" {
		return entry.Name
	}
	return getSpelledOutName(token)
}

func handleDiscoverSubcommand(ifaceName string, persistent, sweepFlag, clearFlag, editFlag bool, targetIP, targetMAC string) error {
	// 1. Cache Clearing Action
	if clearFlag {
		path, err := vssd.GetCachePath()
		if err != nil {
			return err
		}

		// If cache file doesn't exist, tell the user it is already empty
		if _, errStat := os.Stat(path); os.IsNotExist(errStat) {
			if getSystemLanguage() == "de" {
				fmt.Println("  \x1b[1;33m[!] Der Service-Cache ist bereits leer.\x1b[0m")
			} else {
				fmt.Println("  \x1b[1;33m[!] The service cache is already empty.\x1b[0m")
			}
			return nil
		}

		// Ask for confirmation in clean Vane styling
		var response string
		if getSystemLanguage() == "de" {
			fmt.Print("  \x1b[1;33m[?] Möchtest du den Vane-Service-Cache wirklich löschen? [Y/n]:\x1b[0m ")
		} else {
			fmt.Print("  \x1b[1;33m[?] Are you sure you want to clear the Vane service cache? [Y/n]:\x1b[0m ")
		}

		_, _ = fmt.Scanln(&response)
		response = strings.TrimSpace(strings.ToLower(response))

		// Default to Yes if they press Enter (empty response) or input y/yes/ja
		if response == "" || response == "y" || response == "yes" || response == "ja" {
			_ = os.Remove(path)
			if getSystemLanguage() == "de" {
				fmt.Println("  \x1b[1;32m✔ Cache wurde erfolgreich gelöscht!\x1b[0m")
			} else {
				fmt.Println("  \x1b[1;32m✔ Cache cleared successfully!\x1b[0m")
			}
		} else {
			if getSystemLanguage() == "de" {
				fmt.Println("  \x1b[1;31m[x] Löschvorgang abgebrochen.\x1b[0m")
			} else {
				fmt.Println("  \x1b[1;31m[x] Cache clear cancelled.\x1b[0m")
			}
		}
		return nil
	}

	// 2. Interactive Cache Editing Action
	if editFlag {
		return runInteractiveCacheEditor(ifaceName)
	}

	fmt.Println("┌" + strings.Repeat("─", 118) + "┐")
	fmt.Printf("│  vane discover ─ Service Discovery Matrix (Interface: %-63s) │\n", ifaceName)
	fmt.Println("└" + strings.Repeat("─", 118) + "┘")

	var results map[string]vssd.CacheEntry
	var err error

	if sweepFlag || targetIP != "" {
		doneChan := make(chan bool)
		var spinnerWg sync.WaitGroup
		spinnerWg.Add(1)
		go func() {
			defer spinnerWg.Done()
			spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			idx := 0
			for {
				select {
				case <-doneChan:
					fmt.Print("\r\033[K") // Erase spinner line cleanly
					return
				default:
					if targetIP != "" {
						if getSystemLanguage() == "de" {
							fmt.Printf("\r  %s Führe gezieltes Port-Fingerprinting für %s aus... ☕", spinner[idx], targetIP)
						} else {
							fmt.Printf("\r  %s Running targeted port fingerprinting for %s... ☕", spinner[idx], targetIP)
						}
					} else {
						if getSystemLanguage() == "de" {
							fmt.Printf("\r  %s Führe aktiven Nachbarschafts-Sweep aus (%s)... ☕", spinner[idx], ifaceName)
						} else {
							fmt.Printf("\r  %s Running active neighborhood sweep (%s)... ☕", spinner[idx], ifaceName)
						}
					}
					idx = (idx + 1) % len(spinner)
					time.Sleep(80 * time.Millisecond)
				}
			}
		}()

		if targetIP != "" {
			results, err = vssd.RunSingleTargetDiscovery(ifaceName, targetIP, targetMAC)
		} else {
			results, err = vssd.RunTargetedDiscovery(ifaceName)
		}
		close(doneChan)
		spinnerWg.Wait()
		if err != nil {
			return err
		}
	} else {
		// Passive Mode with spinner!
		doneChan := make(chan bool)
		var spinnerWg sync.WaitGroup
		spinnerWg.Add(1)
		go func() {
			defer spinnerWg.Done()
			spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			idx := 0
			for {
				select {
				case <-doneChan:
					fmt.Print("\r\033[K") // Erase spinner line cleanly
					return
				default:
					if getSystemLanguage() == "de" {
						fmt.Printf("\r  %s Lese passiven Cache und löse mDNS-Dienste auf... ☕", spinner[idx])
					} else {
						fmt.Printf("\r  %s Reading passive cache and resolving mDNS services... ☕", spinner[idx])
					}
					idx = (idx + 1) % len(spinner)
					time.Sleep(80 * time.Millisecond)
				}
			}
		}()

		// Passive mode logic
		cacheMap, loadErr := vssd.LoadCacheForInterface(ifaceName)
		results = make(map[string]vssd.CacheEntry)
		if loadErr == nil {
			for k, v := range cacheMap {
				results[k] = v
			}
		}

		// Passive ARP
		arpResults, arpErr := vssd.RunPassiveARPDiscovery(ifaceName)
		if arpErr == nil {
			for k, v := range arpResults {
				if _, exists := results[k]; !exists {
					results[k] = v
				}
			}
		}

		// Passive mDNS
		for _, sig := range vssd.Signatures {
			if _, exists := results[sig.Token]; !exists {
				if v4, v6, found := vssd.LookupMDNSOSResolver(sig.Token); found {
					entry := vssd.CacheEntry{
						IP:              v4,
						IPv6:            v6,
						DiscoveryMethod: "passive_mdns",
						Ports:           sig.Ports,
						LastSeen:        time.Now(),
					}
					results[sig.Token] = entry
				}
			}
		}

		close(doneChan)
		spinnerWg.Wait()
	}

	// Print high-visibility table aligned with gold standard interface matrix
	if getSystemLanguage() == "de" {
		fmt.Println("  SERVICE                     STATUS      IP-ADRESSE                  MAC-ADRESSE        VANE-NOTATION")
	} else {
		fmt.Println("  SERVICE                     STATUS      IP ADDRESS                  MAC ADDRESS        VANE NOTATION")
	}
	fmt.Println(" " + strings.Repeat("─", 120))

	// Filter out completely offline elements to keep TUI clean and professional
	stdOrder := []string{"pve", "nas", "hass", "pi"}
	var activeTokens []string

	// First add std signatures if present and online
	for _, stdTok := range stdOrder {
		if entry, found := results[stdTok]; found && entry.IP != "" {
			activeTokens = append(activeTokens, stdTok)
		}
	}

	// Then gather any custom tokens, sort them alphabetically, and append
	var customTokens []string
	for tok, entry := range results {
		if entry.IP != "" {
			isStd := false
			for _, stdTok := range stdOrder {
				if stdTok == tok {
					isStd = true
					break
				}
			}
			if !isStd {
				customTokens = append(customTokens, tok)
			}
		}
	}
	sort.Strings(customTokens)
	activeTokens = append(activeTokens, customTokens...)

	onlineCount := len(activeTokens)

	if onlineCount == 0 {
		if getSystemLanguage() == "de" {
			fmt.Println("  [!] Keine aktiven Services im Netzwerk gefunden. Nutze \"--sweep\" (-w) für eine aktive Suche.")
		} else {
			fmt.Println("  [!] No active services detected in the network. Use \"--sweep\" (-w) to search actively.")
		}
	} else {
		// We loop over all online service tokens to show status for each
		for _, tok := range activeTokens {
			entry := results[tok]

			// Constant visual column width (11 columns) for status avoids all ANSI padding bugs
			statusCol := "\x1b[1;32m[ONLINE]\x1b[0m   "
			ip := entry.IP
			mac := "───"
			if entry.MAC != "" {
				mac = entry.MAC
			}

			// Format combined notation eno1|>...202 / ...pve
			lastOctet := "───"
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				lastOctet = parts[3]
			}
			coloredNotation := getColoredSyntax(ifaceName, ">", lastOctet)
			combinedNotation := fmt.Sprintf("%s / ...%s", coloredNotation, tok)

			// Save if persistent flag is set, OR if the cache file already exists!
			cachePath, errPath := vssd.GetCachePath()
			cacheExists := false
			if errPath == nil {
				if _, errStat := os.Stat(cachePath); errStat == nil {
					cacheExists = true
				}
			}

			if persistent || cacheExists {
				_ = vssd.UpdateCache(ifaceName, tok, entry)
			}

			// Vertically align bracket abbreviations at exactly column 23
			serviceName := fmt.Sprintf("%-20s(%s)", getSpelledOutNameCustom(tok, entry), tok)

			fmt.Printf("  %-27s %s %-27s %-18s %-35s\n",
				serviceName, statusCol, ip, mac, combinedNotation)

			// Dual-stack IPv6 row printing if present!
			if entry.IPv6 != "" {
				lastFour := "3e8e"
				eui64 := ""
				if entry.MAC != "" {
					if hw, err := net.ParseMAC(entry.MAC); err == nil && len(hw) == 6 {
						eui64 = uip.ComputeEUI64(hw)
						if len(eui64) >= 4 {
							lastFour = strings.ReplaceAll(eui64, ":", "")
							if len(lastFour) >= 4 {
								lastFour = lastFour[len(lastFour)-4:]
							}
						}
					}
				} else if strings.Contains(entry.IPv6, ":") {
					parts := strings.Split(entry.IPv6, ":")
					if len(parts) > 0 && len(parts[len(parts)-1]) > 0 {
						lastFour = parts[len(parts)-1]
					}
				}

				// LAN IPv6 must use Outbound LAN symbol (>) since it is internal to the subnetwork
				coloredV6 := getColoredSyntax(ifaceName, ">", lastFour)
				statusColV6 := "           " // exactly 11 spaces to match statusCol visual width
				fmt.Printf("  %-27s %s %-27s %-18s %-35s\n",
					"", statusColV6, entry.IPv6, "", coloredV6)
			}
		}
	}
	fmt.Println(" " + strings.Repeat("─", 120))

	if persistent {
		if getSystemLanguage() == "de" {
			fmt.Println("\n  \x1b[1;32m✔ Mappings wurden erfolgreich in cache.json gespeichert (chmod 0600)!\x1b[0m")
		} else {
			fmt.Println("\n  \x1b[1;32m✔ Mappings successfully saved to cache.json (chmod 0600)!\x1b[0m")
		}
	} else if sweepFlag || targetIP != "" {
		if getSystemLanguage() == "de" {
			fmt.Println("\n  Tipp: Nutze \"vane discover --persistent\" zum Speichern für lautlose Auflösung!")
		} else {
			fmt.Println("\n  Tip: Use \"vane discover --persistent\" to save mappings for stealthy local resolution!")
		}
	} else {
		if getSystemLanguage() == "de" {
			fmt.Println("\n  Hinweis: Dies zeigt den passiv erkannten Cache-Stand. Nutze \"--sweep\" (-w) für einen aktiven Nachbarschafts-Sweep!")
		} else {
			fmt.Println("\n  Note: This shows the passive cached state. Use \"--sweep\" (-w) to run an active neighborhood sweep!")
		}
	}

	if getSystemLanguage() == "de" {
		fmt.Println("  Tipp: Nutze \"--edit\" (-e) zum händischen Bearbeiten oder \"--clear\" (-c) zum Löschen des Caches.")
	} else {
		fmt.Println("  Tip: Use \"--edit\" (-e) to manually edit or \"--clear\" (-c) to clear the local cache.")
	}
	fmt.Println()

	return nil
}

func runInteractiveCacheEditor(ifaceName string) error {
	path, err := vssd.GetCachePath()
	if err != nil {
		return err
	}

	// Ensure the parent configuration directory exists with owner-only permissions (0700)
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0700)
	cacheExists := true
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cacheExists = false
		_ = os.WriteFile(path, []byte("{}\n"), 0600)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		// 1. Load the entire schema
		schema := make(vssd.CacheSchema)
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &schema)
		}

		// Ensure our interface maps exist in the schema
		ifaceMap, exists := schema[ifaceName]
		if !exists {
			ifaceMap = make(vssd.InterfaceMap)
			schema[ifaceName] = ifaceMap
		}

		// Get all entries for the current interface in a stable order
		var tokens []string
		for tok := range ifaceMap {
			tokens = append(tokens, tok)
		}
		sort.Strings(tokens)

		// 2. Draw the gorgeous colored TUI header
		fmt.Print("\x1b[H\x1b[2J") // Clear screen
		fmt.Println("┌" + strings.Repeat("─", 72) + "┐")
		fmt.Printf("│  \x1b[1;36mvane discover ─ Cache-Verwaltung & Service-Editor (Interface: %-6s)\x1b[0m │\n", ifaceName)
		fmt.Println("└" + strings.Repeat("─", 72) + "┘")

		// 3. Print the list of current cached services
		fmt.Println("\n  \x1b[1;37mAktuelle Einträge im lokalen Cache:\x1b[0m")
		if len(tokens) == 0 {
			if getSystemLanguage() == "de" {
				fmt.Println("    \x1b[90m(Keine Einträge im Cache gefunden)\x1b[0m")
				if !cacheExists {
					fmt.Println("\n    \x1b[1;33m💡 Hinweis: Der Cache ist noch leer, da bisher kein aktiver Scan mit '--persistent' (-p) ausgeführt wurde.\x1b[0m")
					fmt.Println("    \x1b[1;33m   Drücke 'A', um manuell einen neuen Eintrag anzulegen!\x1b[0m")
				}
			} else {
				fmt.Println("    \x1b[90m(No cached service entries found)\x1b[0m")
				if !cacheExists {
					fmt.Println("\n    \x1b[1;33m💡 Note: The cache is currently empty because no active scan with '--persistent' (-p) has been run yet.\x1b[0m")
					fmt.Println("    \x1b[1;33m   Press 'A' to manually add your first service entry!\x1b[0m")
				}
			}
		} else {
			for idx, tok := range tokens {
				entry := ifaceMap[tok]
				portsStr := "───"
				if len(entry.Ports) > 0 {
					var pList []string
					for _, p := range entry.Ports {
						pList = append(pList, strconv.Itoa(p))
					}
					portsStr = strings.Join(pList, ", ")
				}
				displayName := getSpelledOutNameCustom(tok, entry)

				fmt.Printf("    \x1b[1;32m[%d]\x1b[0m \x1b[1;37m%-6s\x1b[0m ➔ \x1b[36m%-20s\x1b[0m \x1b[90m(IP: %-15s | Ports: %s)\x1b[0m\n",
					idx+1, tok, displayName, entry.IP, portsStr)
			}
		}

		// 4. Draw action shortcuts in bold yellow
		fmt.Println("\n  \x1b[1;37mAktionen:\x1b[0m")
		if getSystemLanguage() == "de" {
			fmt.Println("    \x1b[1;33m[A]\x1b[0m Neuen Dienst hinzufügen (Add)")
			fmt.Println("    \x1b[1;33m[E]\x1b[0m Eintrag bearbeiten (Edit)")
			fmt.Println("    \x1b[1;33m[D]\x1b[0m Eintrag löschen (Delete)")
			fmt.Println("    \x1b[1;33m[C]\x1b[0m Cache leeren (Clear)")
			fmt.Println("    \x1b[1;33m[S]\x1b[0m System-Texteditor starten (Raw JSON mit nano/vi)")
			fmt.Println("    \x1b[1;33m[Q]\x1b[0m Beenden (Quit)")
		} else {
			fmt.Println("    \x1b[1;33m[A]\x1b[0m Add new service entry")
			fmt.Println("    \x1b[1;33m[E]\x1b[0m Edit service entry")
			fmt.Println("    \x1b[1;33m[D]\x1b[0m Delete service entry")
			fmt.Println("    \x1b[1;33m[C]\x1b[0m Clear cache completely")
			fmt.Println("    \x1b[1;33m[S]\x1b[0m Start system text editor (Raw JSON)")
			fmt.Println("    \x1b[1;33m[Q]\x1b[0m Quit")
		}

		fmt.Print("\n  \x1b[1;37mAuswahl:\x1b[0m ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToUpper(choice))

		if choice == "Q" {
			fmt.Print("\x1b[H\x1b[2J") // Clear screen on exit
			break
		}

		switch choice {
		case "A":
			// 1. Add new service entry
			fmt.Println("\n  \x1b[1;36m➕ Neuen Dienst händisch hinzufügen:\x1b[0m")

			var tok string
			for {
				fmt.Print("    Kürzel / Token (exakt 3 Buchstaben, z. B. nas): ")
				tokInput, _ := reader.ReadString('\n')
				tokInput = strings.TrimSpace(strings.ToLower(tokInput))
				if tokInput == "" {
					break
				}

				// Validate: exakt 3 Kleinbuchstaben
				isValid := len(tokInput) == 3
				if isValid {
					for _, r := range tokInput {
						if r < 'a' || r > 'z' {
							isValid = false
							break
						}
					}
				}

				if !isValid {
					if getSystemLanguage() == "de" {
						fmt.Println("    \x1b[1;31m❌ Fehler: Das Kürzel muss aus exakt 3 Kleinbuchstaben (a-z) bestehen!\x1b[0m")
					} else {
						fmt.Println("    \x1b[1;31m❌ Error: The token must consist of exactly 3 lowercase letters (a-z)!\x1b[0m")
					}
					continue
				}

				// Check duplicate
				if _, exists := ifaceMap[tokInput]; exists {
					if getSystemLanguage() == "de" {
						fmt.Println("    \x1b[1;31m❌ Fehler: Dieses Kürzel existiert bereits auf diesem Interface!\x1b[0m")
					} else {
						fmt.Println("    \x1b[1;31m❌ Error: This token already exists on this interface!\x1b[0m")
					}
					continue
				}

				tok = tokInput
				break
			}

			if tok == "" {
				continue
			}

			fmt.Print("    Name / Beschreibung (z. B. Portainer Server): ")
			nameInput, _ := reader.ReadString('\n')
			nameInput = strings.TrimSpace(nameInput)

			var ip string
			var autoMAC string
			var autoIPv6 string

			for {
				fmt.Print("    IPv4-Adresse (oder Vane-Notation, z. B. ...45): ")
				ipInput, _ := reader.ReadString('\n')
				ipInput = strings.TrimSpace(ipInput)
				if ipInput == "" {
					break
				}
				resolved, err := validateAndResolveIPInput(ipInput, ifaceName)
				if err != nil {
					if getSystemLanguage() == "de" {
						fmt.Printf("    \x1b[1;31m❌ Fehler: %v\x1b[0m\n", err)
					} else {
						fmt.Printf("    \x1b[1;31m❌ Error: %v\x1b[0m\n", err)
					}
					continue
				}
				ip = resolved

				// Auto-fill assistant logic for MAC and IPv6:
				if tok, found := uip.ExtractToken(ipInput); found {
					// Check if HostPart is hex MAC suffix
					isHex := false
					for _, c := range tok.HostPart {
						if (c < '0' || c > '9') && c != '.' {
							isHex = true
							break
						}
					}
					if len(tok.HostPart) >= 4 && !strings.Contains(tok.HostPart, ".") {
						isHex = true
					}
					if !isHex && !strings.Contains(tok.HostPart, ".") {
						if num, err := strconv.Atoi(tok.HostPart); err == nil && num > 255 {
							isHex = true
						}
					}

					if isHex {
						if fullMAC, errMAC := lookupFullMACFromARP(ifaceName, tok.HostPart); errMAC == nil && fullMAC != "" {
							autoMAC = fullMAC
							if hwAddr, errHW := net.ParseMAC(fullMAC); errHW == nil {
								eui := uip.ComputeEUI64(hwAddr)
								if eui != "" {
									autoIPv6 = "fe80::" + eui
								}
							}
						}
					}
				}
				break
			}
			if ip == "" {
				continue
			}

			var ipv6 string
			for {
				defaultPrompt := ""
				if autoIPv6 != "" {
					defaultPrompt = " [\x1b[90m" + autoIPv6 + "\x1b[0m]"
				}
				fmt.Printf("    IPv6-Adresse (optional, oder Vane-Notation)%s: ", defaultPrompt)
				ipv6Input, _ := reader.ReadString('\n')
				ipv6Input = strings.TrimSpace(ipv6Input)
				if ipv6Input == "" {
					if autoIPv6 != "" {
						ipv6 = autoIPv6
					}
					break
				}
				resolved, err := validateAndResolveIPInput(ipv6Input, ifaceName)
				if err != nil {
					if getSystemLanguage() == "de" {
						fmt.Printf("    \x1b[1;31m❌ Fehler: %v\x1b[0m\n", err)
					} else {
						fmt.Printf("    \x1b[1;31m❌ Error: %v\x1b[0m\n", err)
					}
					continue
				}
				ipv6 = resolved
				break
			}

			defaultMACPrompt := ""
			if autoMAC != "" {
				defaultMACPrompt = " [\x1b[90m" + autoMAC + "\x1b[0m]"
			}
			fmt.Printf("    MAC-Adresse (optional)%s: ", defaultMACPrompt)
			mac, _ := reader.ReadString('\n')
			mac = strings.TrimSpace(mac)
			if mac == "" && autoMAC != "" {
				mac = autoMAC
			}

			fmt.Print("    Offene Ports (kommagetrennt, z. B. 9000, 9443): ")
			portsInput, _ := reader.ReadString('\n')
			portsInput = strings.TrimSpace(portsInput)

			var portsList []int
			if portsInput != "" {
				for _, pStr := range strings.Split(portsInput, ",") {
					if pVal, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil {
						portsList = append(portsList, pVal)
					}
				}
			}

			entry := vssd.CacheEntry{
				IP:              ip,
				IPv6:            ipv6,
				MAC:             mac,
				Name:            nameInput,
				Ports:           portsList,
				DiscoveryMethod: "manual",
				LastSeen:        time.Now(),
			}

			schema[ifaceName][tok] = entry
			saveSchema(path, schema)
			fmt.Println("\n  \x1b[1;32m✔ Dienst erfolgreich hinzugefügt!\x1b[0m")
			time.Sleep(1 * time.Second)

		case "E":
			// 2. Edit existing entry
			if len(tokens) == 0 {
				continue
			}
			fmt.Printf("\n  \x1b[1;36m✏ Welchen Eintrag möchtest du bearbeiten? (1-%d): \x1b[0m", len(tokens))
			numStr, _ := reader.ReadString('\n')
			num, err := strconv.Atoi(strings.TrimSpace(numStr))
			if err != nil || num < 1 || num > len(tokens) {
				continue
			}

			tok := tokens[num-1]
			entry := ifaceMap[tok]

			fmt.Printf("\n  \x1b[1;37mBearbeite %s (%s):\x1b[0m\n", getSpelledOutNameCustom(tok, entry), tok)

			// Edit token if desired
			var newTok string
			for {
				fmt.Printf("    Kürzel / Token [\x1b[90m%s\x1b[0m]: ", tok)
				tokInput, _ := reader.ReadString('\n')
				tokInput = strings.TrimSpace(strings.ToLower(tokInput))
				if tokInput == "" || tokInput == tok {
					newTok = tok
					break
				}

				// Validate
				isValid := len(tokInput) == 3
				if isValid {
					for _, r := range tokInput {
						if r < 'a' || r > 'z' {
							isValid = false
							break
						}
					}
				}

				if !isValid {
					if getSystemLanguage() == "de" {
						fmt.Println("    \x1b[1;31m❌ Fehler: Das Kürzel muss aus exakt 3 Kleinbuchstaben (a-z) bestehen!\x1b[0m")
					} else {
						fmt.Println("    \x1b[1;31m❌ Error: The token must consist of exactly 3 lowercase letters (a-z)!\x1b[0m")
					}
					continue
				}

				// Check duplicate
				if _, exists := ifaceMap[tokInput]; exists {
					if getSystemLanguage() == "de" {
						fmt.Println("    \x1b[1;31m❌ Fehler: Dieses Kürzel existiert bereits auf diesem Interface!\x1b[0m")
					} else {
						fmt.Println("    \x1b[1;31m❌ Error: This token already exists on this interface!\x1b[0m")
					}
					continue
				}

				newTok = tokInput
				break
			}

			fmt.Printf("    Name / Beschreibung [\x1b[90m%s\x1b[0m]: ", entry.Name)
			newNameInput, _ := reader.ReadString('\n')
			newNameInput = strings.TrimSpace(newNameInput)
			if newNameInput != "" {
				entry.Name = newNameInput
			}

			for {
				fmt.Printf("    IPv4-Adresse [\x1b[90m%s\x1b[0m]: ", entry.IP)
				newIPInput, _ := reader.ReadString('\n')
				newIPInput = strings.TrimSpace(newIPInput)
				if newIPInput == "" {
					break
				}
				resolved, err := validateAndResolveIPInput(newIPInput, ifaceName)
				if err != nil {
					if getSystemLanguage() == "de" {
						fmt.Printf("    \x1b[1;31m❌ Fehler: %v\x1b[0m\n", err)
					} else {
						fmt.Printf("    \x1b[1;31m❌ Error: %v\x1b[0m\n", err)
					}
					continue
				}
				entry.IP = resolved

				// Auto-fill assistant logic for MAC and IPv6 during edit:
				if tok, found := uip.ExtractToken(newIPInput); found {
					isHex := false
					for _, c := range tok.HostPart {
						if (c < '0' || c > '9') && c != '.' {
							isHex = true
							break
						}
					}
					if len(tok.HostPart) >= 4 && !strings.Contains(tok.HostPart, ".") {
						isHex = true
					}
					if !isHex && !strings.Contains(tok.HostPart, ".") {
						if num, err := strconv.Atoi(tok.HostPart); err == nil && num > 255 {
							isHex = true
						}
					}

					if isHex {
						if fullMAC, errMAC := lookupFullMACFromARP(ifaceName, tok.HostPart); errMAC == nil && fullMAC != "" {
							entry.MAC = fullMAC
							if hwAddr, errHW := net.ParseMAC(fullMAC); errHW == nil {
								eui := uip.ComputeEUI64(hwAddr)
								if eui != "" {
									entry.IPv6 = "fe80::" + eui
								}
							}
						}
					}
				}
				break
			}

			for {
				fmt.Printf("    IPv6-Adresse [\x1b[90m%s\x1b[0m]: ", entry.IPv6)
				newIPv6Input, _ := reader.ReadString('\n')
				newIPv6Input = strings.TrimSpace(newIPv6Input)
				if newIPv6Input == "" {
					break
				}
				resolved, err := validateAndResolveIPInput(newIPv6Input, ifaceName)
				if err != nil {
					if getSystemLanguage() == "de" {
						fmt.Printf("    \x1b[1;31m❌ Fehler: %v\x1b[0m\n", err)
					} else {
						fmt.Printf("    \x1b[1;31m❌ Error: %v\x1b[0m\n", err)
					}
					continue
				}
				entry.IPv6 = resolved
				break
			}

			fmt.Printf("    MAC-Adresse [\x1b[90m%s\x1b[0m]: ", entry.MAC)
			newMAC, _ := reader.ReadString('\n')
			newMAC = strings.TrimSpace(newMAC)
			if newMAC != "" {
				entry.MAC = newMAC
			}

			var curPorts []string
			for _, p := range entry.Ports {
				curPorts = append(curPorts, strconv.Itoa(p))
			}
			fmt.Printf("    Ports [\x1b[90m%s\x1b[0m]: ", strings.Join(curPorts, ", "))
			newPortsInput, _ := reader.ReadString('\n')
			newPortsInput = strings.TrimSpace(newPortsInput)
			if newPortsInput != "" {
				var portsList []int
				for _, pStr := range strings.Split(newPortsInput, ",") {
					if pVal, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil {
						portsList = append(portsList, pVal)
					}
				}
				entry.Ports = portsList
			}

			entry.LastSeen = time.Now()

			if newTok != tok {
				delete(schema[ifaceName], tok)
			}
			schema[ifaceName][newTok] = entry
			saveSchema(path, schema)
			fmt.Println("\n  \x1b[1;32m✔ Eintrag erfolgreich aktualisiert!\x1b[0m")
			time.Sleep(1 * time.Second)

		case "D":
			// 3. Delete service entry
			if len(tokens) == 0 {
				continue
			}
			fmt.Printf("\n  \x1b[1;31m🗑 Welchen Eintrag möchtest du löschen? (1-%d): \x1b[0m", len(tokens))
			numStr, _ := reader.ReadString('\n')
			num, err := strconv.Atoi(strings.TrimSpace(numStr))
			if err != nil || num < 1 || num > len(tokens) {
				continue
			}

			tok := tokens[num-1]
			delete(schema[ifaceName], tok)
			saveSchema(path, schema)
			fmt.Println("\n  \x1b[1;32m✔ Eintrag erfolgreich gelöscht!\x1b[0m")
			time.Sleep(1 * time.Second)

		case "C":
			// 4. Clear cache completely
			schema[ifaceName] = make(vssd.InterfaceMap)
			saveSchema(path, schema)
			fmt.Println("\n  \x1b[1;32m✔ Cache erfolgreich geleert!\x1b[0m")
			time.Sleep(1 * time.Second)

		case "S":
			// 5. System text editor
			fmt.Println("\n  \x1b[1;36m📝 Starte System-Texteditor...\x1b[0m")
			time.Sleep(500 * time.Millisecond)

			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = "nano"
			}

			cmd := exec.Command(editor, path)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
		}
	}
	return nil
}

func saveSchema(path string, schema vssd.CacheSchema) {
	newData, err := json.MarshalIndent(schema, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, newData, 0600)
	}
}

func validateAndResolveIPInput(input, ifaceName string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("IP address cannot be empty")
	}

	// Check if it is a Vane/UIP notation (e.g. ...33 or eno1|>...33)
	if tok, found := uip.ExtractToken(input); found {
		state, err := netstate.GetInterfaceState(ifaceName)
		if err != nil {
			return "", fmt.Errorf("failed to get interface state for '%s': %v", ifaceName, err)
		}
		resolved, err := uip.ResolveTokenIP(tok, state)
		if err != nil {
			return "", fmt.Errorf("failed to resolve Vane notation: %v", err)
		}
		if net.ParseIP(resolved) == nil {
			return "", fmt.Errorf("resolved notation '%s' to invalid IP '%s'", input, resolved)
		}
		return resolved, nil
	}

	// Otherwise, validate as direct raw IP
	if net.ParseIP(input) == nil {
		return "", fmt.Errorf("invalid IPv4 or IPv6 address syntax")
	}
	return input, nil
}

func lookupFullMACFromARP(ifaceName, suffix string) (string, error) {
	suffix = strings.ToLower(strings.ReplaceAll(suffix, ":", ""))
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetNeighbor -InterfaceAlias '%s' | Select-Object LinkLayerAddress", ifaceName))
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				macClean := strings.ToLower(strings.ReplaceAll(line, "-", ":"))
				cleanMac := strings.ReplaceAll(macClean, ":", "")
				if strings.HasSuffix(cleanMac, suffix) || strings.Contains(cleanMac, suffix) {
					return macClean, nil
				}
			}
		}
		return "", fmt.Errorf("not found")
	}

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
		if len(fields) < 6 {
			continue
		}
		mac := strings.ToLower(fields[3])
		dev := fields[5]

		if dev == ifaceName {
			cleanMac := strings.ReplaceAll(mac, ":", "")
			if strings.HasSuffix(cleanMac, suffix) || strings.Contains(cleanMac, suffix) {
				return mac, nil
			}
		}
	}
	return "", fmt.Errorf("not found")
}
