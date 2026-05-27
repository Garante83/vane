package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"vane/pkg/doc"
	"vane/pkg/netstate"
	"vane/pkg/peeker"
	"vane/pkg/scan"
	"vane/pkg/sniff"
	"vane/pkg/trace"
	"vane/pkg/transfer"
	"vane/pkg/uip"
)

func main() {
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
