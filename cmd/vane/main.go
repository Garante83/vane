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
	"vane/pkg/parser"
	"vane/pkg/peeker"
	"vane/pkg/scan"
	"vane/pkg/sniff"
	"vane/pkg/trace"
	"vane/pkg/transfer"
)

type Translation struct {
	ErrorNoIPv4      string
	ErrorNoIPv6      string
	ErrorModifier    string
	ErrorTooFewArgs  string
	UsageConvert     string
	ErrorNoIPConvert string
	PreFlightFail    string
	ApipaDetected    string
	ErrorGateway     string
	HelpTitle        string
	HelpUsageHeader  string
	HelpExecCommand  string
	HelpConvert      string
	HelpScan         string
	HelpTrace        string
	HelpSend         string
	HelpRecv         string
	HelpSniff        string
	HelpManual       string
	HelpMatrix       string
	ConvertULA       string
	ConvertIPv4Equiv string
	NoIPBound        string
	ErrorMACMismatch string
}

var de = Translation{
	ErrorNoIPv4:      "[vane] Error: Keine valide IPv4-Adresse auf Interface %s.\n",
	ErrorNoIPv6:      "[vane] Error: Keine globale IPv6-Adresse (GUA) auf Interface %s.\n",
	ErrorModifier:    "[vane] Error: Unbekannter Richtungs-Modifikator '%s'.\n",
	ErrorTooFewArgs:  "[vane] Error: Zu wenige Argumente für Konvertierungs-Modus.\n",
	UsageConvert:     "Verwendung: vane -c <interface> <wert>\n",
	ErrorNoIPConvert: "[vane] Error: Keine IPv4-Adresse auf %s verfügbar.\n",
	PreFlightFail:    "[!] vane ─ Port %s auf %s ist nicht erreichbar (Timeout / Firewall blockiert)\n",
	ApipaDetected:    "[!] vane ─ APIPA erkannt auf %s (DHCP-FAIL)\n",
	ErrorGateway:     "[vane] Error: Standard-Gateway für Interface %s konnte nicht ermittelt werden: %v\n",
	HelpTitle:        "vane ─ Der smarte CLI-Netzwerk-Proxy",
	HelpUsageHeader:  "\nVerwendung:",
	HelpExecCommand:  "  vane <befehl> [argumente...]    Führt einen Befehl mit Vane-Syntax-Ersetzung aus.",
	HelpConvert:      "  vane -c <interface> <wert>      Konvertiert einen Hex- oder v4-Wert (Infocenter).",
	HelpScan:         "  vane scan [interface]           Scanned das aktive Subnetz des Interfaces (High-Visibility).",
	HelpTrace:        "  vane trace <ziel>               Führt eine interaktive Latenz- & Route-Analyse (MTR) durch.",
	HelpSend:         "  vane send <datei> --code <code> Sendet eine Datei hochperformant & verschlüsselt an einen Peer.",
	HelpRecv:         "  vane recv [--port <port>]       Empfängt eine Datei hochperformant & verschlüsselt.",
	HelpSniff:        "  vane sniff [interface]          Liest HTTP & DNS Anfragen auf dem Interface live mit.",
	HelpManual:       "  vane doc / man                  Öffnet das interaktive TUI-Handbuch (System-Dokumentation).",
	HelpMatrix:       "  vane                            Zeigt die Local Network Interface Matrix.",
	ConvertULA:       "-> ULA (Intern):  %s%s\n",
	ConvertIPv4Equiv: "-> IPv4-Äquivalent: %s\n",
	NoIPBound:        "Keine IP gebunden",
	ErrorMACMismatch: "[vane] Error: MAC-Suffix '%s' stimmt nicht mit Interface %s überein.\n",
}

var en = Translation{
	ErrorNoIPv4:      "[vane] Error: No valid IPv4 address on interface %s.\n",
	ErrorNoIPv6:      "[vane] Error: No global IPv6 address (GUA) on interface %s.\n",
	ErrorModifier:    "[vane] Error: Unknown direction modifier '%s'.\n",
	ErrorTooFewArgs:  "[vane] Error: Too few arguments for conversion mode.\n",
	UsageConvert:     "Usage: vane -c <interface> <value>\n",
	ErrorNoIPConvert: "[vane] Error: No IPv4 address available on %s.\n",
	PreFlightFail:    "[!] vane ─ Port %s on %s is unreachable (Timeout / Firewall Blocked)\n",
	ApipaDetected:    "[!] vane ─ APIPA Detected on %s (DHCP-FAIL)\n",
	ErrorGateway:     "[vane] Error: Could not determine default gateway for interface %s: %v\n",
	HelpTitle:        "vane ─ The smart CLI network proxy",
	HelpUsageHeader:  "\nUsage:",
	HelpExecCommand:  "  vane <command> [arguments...]    Executes a command with Vane syntax substitution.",
	HelpConvert:      "  vane -c <interface> <value>      Converts a hex or v4 value (Infocenter).",
	HelpScan:         "  vane scan [interface]           Scans the active subnet of the interface (High-Visibility).",
	HelpTrace:        "  vane trace <target>             Performs an interactive routing latency analysis (MTR).",
	HelpSend:         "  vane send <file> --code <code>   Sends a file with high performance & encryption to a peer.",
	HelpRecv:         "  vane recv [--port <port>]        Receives a file with high performance & encryption.",
	HelpSniff:        "  vane sniff [interface]           Sniffs live HTTP & DNS requests on the interface.",
	HelpManual:       "  vane doc / man                  Opens the interactive TUI manual (system documentation).",
	HelpMatrix:       "  vane                             Shows the Local Network Interface Matrix.",
	ConvertULA:       "-> ULA (Internal): %s%s\n",
	ConvertIPv4Equiv: "-> IPv4 Equivalent: %s\n",
	NoIPBound:        "No IP bound",
	ErrorMACMismatch: "[vane] Error: MAC suffix '%s' does not match interface %s.\n",
}

var msg = en

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
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
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
			if t, isVane := parser.ExtractToken(ifaceName); isVane {
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
		if t, isVane := parser.ExtractToken(target); isVane {
			state, err := netstate.GetInterfaceState(t.Interface)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
				os.Exit(1)
			}
			target = resolveTokenIP(t, state)
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
			if t, isVane := parser.ExtractToken(ifaceName); isVane {
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
	var targetToken *parser.Token
	var tokenArgIndex = -1

	for i := 2; i < len(os.Args); i++ {
		t, isVane := parser.ExtractToken(os.Args[i])
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

	targetIP := resolveTokenIP(targetToken, state)

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

// resolveIPv4Dots formats the local IPv4 address by overriding octets relative to the dot count
func resolveIPv4Dots(localIP net.IP, dotCount int, hostPart string) string {
	parts := strings.Split(localIP.String(), ".")
	if dotCount > 0 && dotCount <= len(parts) {
		return strings.Join(parts[:dotCount], ".") + "." + hostPart
	}
	return hostPart
}

// resolveIPv6WAN resolves a global unicast WAN IPv6 address using EUI-64 or hybrid injection
func resolveIPv6WAN(globalIP net.IP, hostPart string, mac net.HardwareAddr) string {
	// Default to hardware EUI-64 MAC suffix derivation if host part is empty or zero
	if hostPart == "0" || hostPart == "" {
		eui64 := computeEUI64(mac)
		if eui64 != "" {
			prefixStr := getPrefix64(globalIP, "2000::")
			return prefixStr + ":" + eui64
		}
	}

	prefix := globalIP.Mask(net.CIDRMask(64, 128))
	num, _ := strconv.Atoi(hostPart)

	// Inject suffix bytes directly into the interface identifier portion
	prefix[14] = byte(num >> 8)
	prefix[15] = byte(num)

	return prefix.String()
}

// computeEUI64 calculates the standard 64-bit EUI-64 identifier from a 6-byte hardware MAC
func computeEUI64(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	// Invert the Universal/Local bit (7th bit of 1st octet)
	b0 := mac[0] ^ 0x02
	return fmt.Sprintf("%02x%02x:%02xff:fe%02x:%02x%02x", b0, mac[1], mac[2], mac[3], mac[4], mac[5])
}

// getPrefix64 extracts the /64 routing prefix of an IPv6 address
func getPrefix64(ip net.IP, fallback string) string {
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
			eui64 = computeEUI64(state.HardwareAddr)
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
		ipv4Str = resolveIPv4Dots(state.IPv4Local, dots, val)
	}

	eui64 := "1ac0:4dff:feda:3e8e"
	if len(state.HardwareAddr) == 6 {
		eui64 = computeEUI64(state.HardwareAddr)
	}

	linkLocal := "fe80::" + eui64
	ulaPrefix := getPrefix64(state.IPv6ULA, "fd99:9731:b7c6:0:")
	globalPrefix := getPrefix64(state.IPv6Global, "2002:d5b6:7403:0:")

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

		if isLoopback {
			typeStr = "Loopback"
		} else if isWlan {
			typeStr = "WLAN"
		} else if state.IsAPIPA {
			typeStr = "APIPA"
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
				gwIP, err := getDefaultGateway(iface.Name)
				if err == nil && gwIP != "" {
					gwType := "(Gateway)"
					gwSyntax := getColoredSyntax(iface.Name, ">", "gw")
					fmt.Printf("  %-11s %-9s %-10s %s %s\n", "", "", gwType, gwSyntax, gwIP)
				}
			}

			if hasV6 {
				eui64 := ""
				if len(state.HardwareAddr) == 6 {
					eui64 = computeEUI64(state.HardwareAddr)
				}
				lastFour := "3e8e"
				if len(eui64) >= 4 {
					lastFour = strings.ReplaceAll(eui64, ":", "")
					if len(lastFour) >= 4 {
						lastFour = lastFour[len(lastFour)-4:]
					}
				}

				prefixStr := getPrefix64(state.IPv6Global, "2001:9731:")
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

// getDefaultGateway retrieves the active IPv4 default gateway for a local interface
func getDefaultGateway(ifaceName string) (string, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetRoute -InterfaceAlias '%s' -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop", ifaceName))
		out, err := cmd.Output()
		if err != nil {
			cmdFallback := exec.Command("powershell", "-NoProfile", "-Command",
				"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop")
			outFallback, errFallback := cmdFallback.Output()
			if errFallback == nil && len(strings.TrimSpace(string(outFallback))) > 0 {
				return strings.TrimSpace(string(outFallback)), nil
			}
			return "", fmt.Errorf("failed to detect gateway on Windows: %v", err)
		}
		ip := strings.TrimSpace(string(out))
		if ip == "" || ip == "0.0.0.0" {
			return "", fmt.Errorf("no default gateway configured")
		}
		return ip, nil
	}

	// Linux /proc/net/route table scanner
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

// resolveTokenIP is the centralized engine for converting a Vane notation token into a raw IP address
func resolveTokenIP(targetToken *parser.Token, state *netstate.State) string {
	var targetIP string

	// Direct parsing logic based on direction modifier
	switch targetToken.Direction {
	case ">": // Outbound LAN (Dual-Stack: IPv6 ULA first, fallback to IPv4)
		useIPv6 := false
		if state.IPv6ULA != nil {
			useIPv6 = true
		}

		if useIPv6 {
			// Resolve using IPv6 ULA
			if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
				gw, err := getIPv6DefaultGateway(state.InterfaceName)
				if err == nil && gw != "" {
					targetIP = gw
				} else {
					// Fallback to IPv4 gateway if IPv6 gateway isn't found
					if state.IPv4Local != nil {
						gwV4, errV4 := getDefaultGateway(state.InterfaceName)
						if errV4 == nil && gwV4 != "" {
							targetIP = gwV4
						} else {
							fmt.Fprintf(os.Stderr, msg.ErrorGateway, state.InterfaceName, err)
							os.Exit(1)
						}
					} else {
						fmt.Fprintf(os.Stderr, msg.ErrorGateway, state.InterfaceName, err)
						os.Exit(1)
					}
				}
			} else {
				// Replace the last group of the ULA address with HostPart
				targetIP = resolveIPv6ULA(state.IPv6ULA, targetToken.HostPart)
			}
		} else {
			// Fallback to IPv4
			if state.IPv4Local == nil {
				// Final extreme fallback: if IPv6 GUA is active, try it as a last resort
				if state.IPv6Global != nil {
					if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
						gw, err := getIPv6DefaultGateway(state.InterfaceName)
						if err == nil && gw != "" {
							targetIP = gw
							break
						}
					}
					targetIP = resolveIPv6ULA(state.IPv6Global, targetToken.HostPart)
					break
				}

				fmt.Fprintf(os.Stderr, msg.ErrorNoIPv4, targetToken.Interface)
				os.Exit(1)
			}

			// Passive APIPA validation check to catch DHCP lease errors early
			if state.IsAPIPA {
				fmt.Fprintf(os.Stderr, msg.ApipaDetected, targetToken.Interface)
				os.Exit(1)
			}

			// Dynamic gateway resolution for 'gw' or 'router' keywords
			if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
				gw, err := getDefaultGateway(state.InterfaceName)
				if err != nil {
					fmt.Fprintf(os.Stderr, msg.ErrorGateway, state.InterfaceName, err)
					os.Exit(1)
				}
				targetIP = gw
			} else {
				// Check if HostPart is a MAC/EUI-64 suffix (contains non-digits or has a length of 4 or more)
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
					// Check local interface MAC first
					eui64 := ""
					if len(state.HardwareAddr) == 6 {
						eui64 = computeEUI64(state.HardwareAddr)
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
						// True subnet resolution: scan kernel ARP table to resolve remote IP!
						resolvedIP, err := resolveRemoteIPFromARP(state.InterfaceName, targetToken.HostPart)
						if err == nil && resolvedIP != "" {
							targetIP = resolvedIP
						} else {
							fmt.Fprintf(os.Stderr, msg.ErrorMACMismatch, targetToken.HostPart, state.InterfaceName)
							os.Exit(1)
						}
					}
				} else {
					targetIP = resolveIPv4Dots(state.IPv4Local, targetToken.Dots, targetToken.HostPart)
				}
			}
		}

	case "<": // External WAN (IPv6)
		if state.IPv6Global == nil {
			fmt.Fprintf(os.Stderr, msg.ErrorNoIPv6, targetToken.Interface)
			os.Exit(1)
		}

		targetIP = resolveIPv6WAN(state.IPv6Global, targetToken.HostPart, state.HardwareAddr)

	case ":": // Loopback (lo)
		if targetToken.HostPart == "1" {
			targetIP = "::1"
		} else {
			baseIP := net.ParseIP("127.0.0.1")
			if state.IPv4Local != nil {
				baseIP = state.IPv4Local
			}
			targetIP = resolveIPv4Dots(baseIP, targetToken.Dots, targetToken.HostPart)
		}

	case "!": // APIPA (DHCP-FAIL fallback)
		if state.IPv4Local != nil && state.IsAPIPA {
			targetIP = resolveIPv4Dots(state.IPv4Local, targetToken.Dots, targetToken.HostPart)
		} else {
			parts := []string{"169", "254", "0", targetToken.HostPart}
			targetIP = strings.Join(parts, ".")
		}

	default:
		fmt.Fprintf(os.Stderr, msg.ErrorModifier, targetToken.Direction)
		os.Exit(1)
	}

	return targetIP
}

// handleAutocomplete processes autocomplete inputs from the shell script
func handleAutocomplete(words []string) {
	if len(words) <= 1 {
		// Suggest main commands
		fmt.Println("ping scan trace sniff send recv doc man help")
		return
	}

	subCmd := words[1]

	// If we are at the second word (e.g. vane p[Tab])
	if len(words) == 2 {
		fmt.Println("ping scan trace sniff send recv doc man help")
		return
	}

	// Dynamic suggestions for commands that take an interface or target
	if subCmd == "ping" || subCmd == "scan" || subCmd == "trace" || subCmd == "sniff" || subCmd == "check" {
		// Only suggest on the first argument after the command (e.g., vane ping [Tab])
		if len(words) == 3 {
			var suggestions []string

			// Gather interfaces and active indices
			ifaces, err := net.Interfaces()
			if err == nil {
				activeCount := 0
				for _, iface := range ifaces {
					isUp := (iface.Flags & net.FlagUp) != 0
					isLoopback := (iface.Flags & net.FlagLoopback) != 0

					if isLoopback {
						suggestions = append(suggestions, iface.Name)
						suggestions = append(suggestions, "0")
						suggestions = append(suggestions, "\"0|:...1\"")
					} else if isUp {
						activeCount++
						suggestions = append(suggestions, iface.Name)
						suggestions = append(suggestions, strconv.Itoa(activeCount))

						// Add a helpful syntax suggestion based on active IP (v4 or gateway)
						state, err := netstate.GetInterfaceState(iface.Name)
						if err == nil {
							if state.IPv4Local != nil {
								lastOctet := "53"
								parts := strings.Split(state.IPv4Local.String(), ".")
								if len(parts) == 4 {
									lastOctet = parts[3]
								}
								suggestions = append(suggestions, fmt.Sprintf("\"%d|>...%s\"", activeCount, lastOctet))
								suggestions = append(suggestions, fmt.Sprintf("\"%s|>...%s\"", iface.Name, lastOctet))
							}
							gwIP, err := getDefaultGateway(iface.Name)
							if err == nil && gwIP != "" {
								suggestions = append(suggestions, fmt.Sprintf("\"%d|>...gw\"", activeCount))
								suggestions = append(suggestions, fmt.Sprintf("\"%s|>...gw\"", iface.Name))
							}
						}
					}
				}
			}

			fmt.Println(strings.Join(suggestions, " "))
			return
		}
	}
}

func printAutocompleteHelp() {
	if getSystemLanguage() == "de" {
		fmt.Println("vane autocomplete ─ Intelligente shell-spezifische Autovervollständigung")
		fmt.Println("\nNutzung:")
		fmt.Println("  vane autocomplete script         Gibt das universelle Shell-Vervollständigungsskript aus.")
		fmt.Println("\nInstallation:")
		fmt.Println("  Füge die folgende Zeile am Ende deiner ~/.bashrc (oder ~/.zshrc) hinzu:")
		fmt.Println("  source <(vane autocomplete script)")
		fmt.Println("\nFunktionsweise:")
		fmt.Println("  Nach der Installation vervollständigt Vane automatisch:")
		fmt.Println("  - Befehle (ping, scan, trace, sniff, etc.)")
		fmt.Println("  - Schnittstellennamen (eno1, lo)")
		fmt.Println("  - Numerische Schnittstellen-Indizes ([0], [1])")
		fmt.Println("  - Vane-Syntaxvorlagen (z.B. \"1|>...gw\")")
	} else {
		fmt.Println("vane autocomplete ─ Intelligent Shell Autocompletion Engine")
		fmt.Println("\nUsage:")
		fmt.Println("  vane autocomplete script         Outputs the universal shell completion script.")
		fmt.Println("\nInstallation:")
		fmt.Println("  Add the following line to the end of your ~/.bashrc (or ~/.zshrc):")
		fmt.Println("  source <(vane autocomplete script)")
		fmt.Println("\nFeatures:")
		fmt.Println("  Once installed, Vane will automatically complete:")
		fmt.Println("  - Commands (ping, scan, trace, sniff, etc.)")
		fmt.Println("  - Interface names (eno1, lo)")
		fmt.Println("  - Numeric interface indices ([0], [1])")
		fmt.Println("  - Vane syntax templates (e.g. \"1|>...gw\")")
	}
}

func printCompletionScript() {
	script := `# Bash & Zsh completion for vane
_vane_completions() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Call vane to get dynamic completions
    local completions
    completions=$(vane autocomplete --complete "${COMP_WORDS[@]:0:COMP_CWORD+1}")

    COMPREPLY=( $(compgen -W "$completions" -- "$cur") )
    return 0
}

# Register completion
if [ -n "$BASH_VERSION" ]; then
    complete -F _vane_completions vane
elif [ -n "$ZSH_VERSION" ]; then
    autoload -U +X bashcompinit && bashcompinit
    complete -F _vane_completions vane
fi
`
	fmt.Print(script)
}

// getIPv6DefaultGateway retrieves the active IPv6 default gateway for an interface
func getIPv6DefaultGateway(ifaceName string) (string, error) {
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

		// destHex == "00000000000000000000000000000000" means default route (::/0)
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

// resolveIPv6ULA replaces the final hex segment group of an IPv6 Unique Local Address
func resolveIPv6ULA(ula net.IP, hostPart string) string {
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

// resolveRemoteIPFromARP reads the dynamic system ARP table cache to map MAC hex suffixes to local subnet IPs
func resolveRemoteIPFromARP(ifaceName, suffix string) (string, error) {
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
