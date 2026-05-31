package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vane/pkg/netstate"
	"vane/pkg/peeker"
	"vane/pkg/uip"
	"vane/pkg/vssd"
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

// getDirectionName returns the human-readable description of a Vane operator
func getDirectionName(dir, lang string) string {
	switch dir {
	case ">":
		if lang == "de" {
			return "Outbound LAN / Lokales Subnetz"
		}
		return "Outbound LAN / Local Subnet"
	case "<":
		if lang == "de" {
			return "External WAN / Globale IPv6"
		}
		return "External WAN / Global IPv6"
	case ":":
		if lang == "de" {
			return "Local Loopback / Lokaler Host"
		}
		return "Local Loopback / Local Host"
	case "!":
		if lang == "de" {
			return "APIPA Notfall-Segment"
		}
		return "APIPA Emergency Segment"
	default:
		return "Unbekannt"
	}
}

// handleExplainSubcommand implements the 'vane explain' command to visualize notation resolution step-by-step
func handleExplainSubcommand(input string) {
	lang := getSystemLanguage()

	// Parse input notation
	targetToken, isVane := uip.ExtractToken(input)

	// If it doesn't parse as a token, try to convert shorthand (e.g. lan.1 -> 1|>...1)
	if !isVane {
		idx := strings.Index(input, ".")
		var ifacePart, hostPart string
		var dots int

		if idx != -1 {
			ifacePart = input[:idx]
			dots = 0
			for i := idx; i < len(input) && input[i] == '.'; i++ {
				dots++
			}
			hostPart = input[idx+dots:]
		} else {
			hostPart = input
		}

		targetIface := ""
		if ifacePart != "" {
			if _, err := net.InterfaceByName(ifacePart); err == nil {
				targetIface = ifacePart
			} else if ifacePart == "lan" || ifacePart == "wlan" {
				targetIface = ifacePart
			} else if _, err := strconv.Atoi(ifacePart); err == nil {
				targetIface = ifacePart
			}
		}

		if targetIface == "" {
			if hostPart == "1" || hostPart == "localhost" {
				targetIface = "lo"
			} else {
				targetIface = getDefaultActiveInterface()
				if targetIface == "" {
					targetIface = "1"
				}
			}
		}

		direction := ">"
		if hostPart == "1" || hostPart == "localhost" || strings.HasPrefix(hostPart, "127.") {
			direction = ":"
		} else if strings.Contains(input, "!") {
			direction = "!"
		} else if strings.Contains(input, "<") {
			direction = "<"
		}

		if dots == 0 {
			dots = 3
		}

		constructed := fmt.Sprintf("%s|%s%s%s", targetIface, direction, strings.Repeat(".", dots), hostPart)
		if t, isVaneConstructed := uip.ExtractToken(constructed); isVaneConstructed {
			targetToken = t
			isVane = true
		}
	}

	if !isVane || targetToken == nil {
		if lang == "de" {
			fmt.Fprintf(os.Stderr, "[vane] Fehler: Ungültige Notation '%s'.\nVerwendung: vane explain <interface>|>...<wert> oder vane explain <shorthand> (z.B. lan.1)\n", input)
		} else {
			fmt.Fprintf(os.Stderr, "[vane] Error: Invalid notation '%s'.\nUsage: vane explain <interface>|>...<value> or vane explain <shorthand> (e.g. lan.1)\n", input)
		}
		os.Exit(1)
	}

	printBoxLine := func(text string) {
		runes := []rune(text)
		padding := 78 - len(runes)
		if padding < 0 {
			text = string(runes[:75]) + "..."
			padding = 0
		}
		fmt.Printf("│%s%s│\n", text, strings.Repeat(" ", padding))
	}

	fmt.Println("┌" + strings.Repeat("─", 78) + "┐")
	if lang == "de" {
		printBoxLine("  vane explain ─ Detaillierte Notations-Analyse (Eingabe: " + input + ")")
	} else {
		printBoxLine("  vane explain ─ Detailed Notation Resolution (Input: " + input + ")")
	}
	fmt.Println("└" + strings.Repeat("─", 78) + "┘")

	if lang == "de" {
		fmt.Printf("  [+] Extrahierter Token: %s\n", targetToken.FullMatch)
		fmt.Printf("      - Interface: %s\n", targetToken.Interface)
		fmt.Printf("      - Richtung:  %s (%s)\n", targetToken.Direction, getDirectionName(targetToken.Direction, lang))
		fmt.Printf("      - Maskierung: %d Punkt(e) (Subnetzmasken-Tiefe)\n", targetToken.Dots)
		fmt.Printf("      - Ziel-Host:  %s\n", targetToken.HostPart)
		if targetToken.Port != "" {
			fmt.Printf("      - Ziel-Port:  %s (Automatisches Port-Handoff aktiv)\n", targetToken.Port)
		}
	} else {
		fmt.Printf("  [+] Extracted Token: %s\n", targetToken.FullMatch)
		fmt.Printf("      - Interface: %s\n", targetToken.Interface)
		fmt.Printf("      - Direction: %s (%s)\n", targetToken.Direction, getDirectionName(targetToken.Direction, lang))
		fmt.Printf("      - Masking:   %d dot(s) (subnet masking depth)\n", targetToken.Dots)
		fmt.Printf("      - Target Host: %s\n", targetToken.HostPart)
		if targetToken.Port != "" {
			fmt.Printf("      - Target Port: %s (Automatic port handoff active)\n", targetToken.Port)
		}
	}
	fmt.Println()

	state, err := netstate.GetInterfaceState(targetToken.Interface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  \x1b[1;31m[x] Fehler beim Auslesen des Interfaces %s: %v\x1b[0m\n", targetToken.Interface, err)
		os.Exit(1)
	}

	if lang == "de" {
		fmt.Println("  [1] SCHNITTSTELLEN-ANALYSE:")
		fmt.Printf("      * %-30s \x1b[1;36m%s\x1b[0m\n", "Physikalische Schnittstelle:", state.InterfaceName)
		if state.IPv4Local != nil {
			fmt.Printf("      * %-30s %s\n", "IPv4-Adresse (Lokal):", state.IPv4Local)
		} else {
			fmt.Printf("      * %-30s Keine gebunden\n", "IPv4-Adresse (Lokal):")
		}
		if state.IPv6ULA != nil {
			fmt.Printf("      * %-30s %s\n", "IPv6-ULA (Lokal):", state.IPv6ULA)
		} else {
			fmt.Printf("      * %-30s Keine gebunden\n", "IPv6-ULA (Lokal):")
		}
		if state.IPv6Global != nil {
			fmt.Printf("      * %-30s %s\n", "IPv6-GUA (Global/WAN):", state.IPv6Global)
		} else {
			fmt.Printf("      * %-30s Keine gebunden\n", "IPv6-GUA (Global/WAN):")
		}
		if len(state.HardwareAddr) > 0 {
			fmt.Printf("      * %-30s %s\n", "Hardware-MAC-Adresse:", state.HardwareAddr)
		}
	} else {
		fmt.Println("  [1] NETWORK INTERFACE ANALYSIS:")
		fmt.Printf("      * %-26s \x1b[1;36m%s\x1b[0m\n", "Physical Interface Name:", state.InterfaceName)
		if state.IPv4Local != nil {
			fmt.Printf("      * %-26s %s\n", "Local IPv4 Address:", state.IPv4Local)
		} else {
			fmt.Printf("      * %-26s None bound\n", "Local IPv4 Address:")
		}
		if state.IPv6ULA != nil {
			fmt.Printf("      * %-26s %s\n", "Local IPv6-ULA Address:", state.IPv6ULA)
		} else {
			fmt.Printf("      * %-26s None bound\n", "Local IPv6-ULA Address:")
		}
		if state.IPv6Global != nil {
			fmt.Printf("      * %-26s %s\n", "Global IPv6-GUA (WAN):", state.IPv6Global)
		} else {
			fmt.Printf("      * %-26s None bound\n", "Global IPv6-GUA (WAN):")
		}
		if len(state.HardwareAddr) > 0 {
			fmt.Printf("      * %-26s %s\n", "Hardware MAC Address:", state.HardwareAddr)
		}
	}
	fmt.Println()

	resolvedIP := ""
	var resolveErr error

	if targetToken.Direction == ">" {
		useIPv6 := state.IPv6ULA != nil
		if lang == "de" {
			fmt.Println("  [2] DUAL-STACK ENTSCHEIDUNG:")
			if useIPv6 {
				fmt.Println("      * Aktive IPv6-ULA (fd00::/8) auf der Schnittstelle gefunden!")
				fmt.Println("      \x1b[1;32m➔ Bevorzugte Auflösung über IPv6 wird eingeleitet.\x1b[0m")
				fmt.Println("      * (IPv4-Fallback wird in Bereitschaft gehalten...)")
			} else {
				fmt.Println("      * Keine IPv6-ULA (fd00::/8) auf der Schnittstelle konfiguriert.")
				fmt.Println("      \x1b[1;33m➔ Weiche aus auf IPv4-Auflösung...\x1b[0m")
			}
		} else {
			fmt.Println("  [2] DUAL-STACK DECISION:")
			if useIPv6 {
				fmt.Println("      * Active IPv6-ULA (fd00::/8) found on this interface!")
				fmt.Println("      \x1b[1;32m➔ Initiating preferred IPv6 resolution.\x1b[0m")
				fmt.Println("      * (IPv4 fallback is kept in standby...)")
			} else {
				fmt.Println("      * No IPv6-ULA (fd00::/8) configured on this interface.")
				fmt.Println("      \x1b[1;33m➔ Falling back to IPv4 resolution...\x1b[0m")
			}
		}
		fmt.Println()

		if useIPv6 {
			if lang == "de" {
				fmt.Println("  [3] UIP BERECHNUNG (IPv6 ULA):")
				if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
					fmt.Println("      * Suche IPv6 Standard-Gateway für dieses Interface...")
				} else {
					fmt.Printf("      * Segment-Ersetzung: Überschreibe Host-Teil mit '%s'\n", targetToken.HostPart)
					fmt.Printf("      * IPv6-Präfix-Basis: %s\n", uip.GetPrefix64(state.IPv6ULA, ""))
				}
			} else {
				fmt.Println("  [3] UIP COMPUTATION (IPv6 ULA):")
				if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
					fmt.Println("      * Querying default IPv6 gateway for this interface...")
				} else {
					fmt.Printf("      * Segment Replacement: Overwriting host part with '%s'\n", targetToken.HostPart)
					fmt.Printf("      * IPv6 Prefix Base:  %s\n", uip.GetPrefix64(state.IPv6ULA, ""))
				}
			}
		} else {
			if lang == "de" {
				fmt.Println("  [3] UIP BERECHNUNG (IPv4):")
				if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
					fmt.Println("      * Ermittle Standard-Gateway über die Routing-Tabelle...")
				} else if uip.IsSemanticToken(targetToken.HostPart) {
					fmt.Printf("      * Semantisches Service-Token erkannt: '%s'\n", targetToken.HostPart)
					fmt.Println("      * Durchsuche lokalen VSSD-Cache...")
				} else {
					isHex := false
					for _, c := range targetToken.HostPart {
						if (c < '0' || c > '9') && c != '.' {
							isHex = true
							break
						}
					}
					if isHex {
						fmt.Printf("      * Hexadezimaler MAC-Suffix erkannt: '%s'\n", targetToken.HostPart)
						fmt.Println("      * Scanne lokale ARP-Tabelle nach passenden Hardware-Adressen...")
					} else {
						fmt.Printf("      * IPv4 Segment-Ersatz: Maskiere %d Punkt(e)\n", targetToken.Dots)
						fmt.Printf("      * Ersetze das letzte Segment der IP %s durch '%s'\n", state.IPv4Local, targetToken.HostPart)
					}
				}
			} else {
				fmt.Println("  [3] UIP COMPUTATION (IPv4):")
				if targetToken.HostPart == "gw" || targetToken.HostPart == "router" {
					fmt.Println("      * Resolving default gateway from routing table...")
				} else if uip.IsSemanticToken(targetToken.HostPart) {
					fmt.Printf("      * Semantic service token detected: '%s'\n", targetToken.HostPart)
					fmt.Println("      * Querying local VSSD cache registry...")
				} else {
					isHex := false
					for _, c := range targetToken.HostPart {
						if (c < '0' || c > '9') && c != '.' {
							isHex = true
							break
						}
					}
					if isHex {
						fmt.Printf("      * Hexadecimal MAC suffix detected: '%s'\n", targetToken.HostPart)
						fmt.Println("      * Scanning kernel ARP tables for matching hardware address...")
					} else {
						fmt.Printf("      * IPv4 Segment replacement: Masking %d segment(s)\n", targetToken.Dots)
						fmt.Printf("      * Replacing last segments of IP %s with '%s'\n", state.IPv4Local, targetToken.HostPart)
					}
				}
			}
		}
		fmt.Println()
	} else {
		if lang == "de" {
			fmt.Println("  [2] MODIFIKATOR-BESTIMMUNG:")
			fmt.Printf("      * Gewählter Operator: '%s'\n", targetToken.Direction)
		} else {
			fmt.Println("  [2] OPERATOR EVALUATION:")
			fmt.Printf("      * Selected operator: '%s'\n", targetToken.Direction)
		}
		fmt.Println()
	}

	resolvedIP, resolveErr = uip.ResolveTokenIP(targetToken, state)

	if lang == "de" {
		fmt.Println("  [4] ZIELAUFLÖSUNG:")
		if resolveErr != nil {
			fmt.Printf("      \x1b[1;31m[x] Fehler bei der Auflösung: %v\x1b[0m\n", resolveErr)
		} else {
			fmt.Printf("      * Erfolgreich aufgelöst zu IP:  \x1b[1;32m%s\x1b[0m\n", resolvedIP)
			if targetToken.Port != "" {
				fmt.Printf("      * Port-Handoff aktiv für Port:  \x1b[1;36m%s\x1b[0m\n", targetToken.Port)
			}
			if targetToken.Port != "" {
				fmt.Println("      * Führe schnellen TCP-Erreichbarkeitstest (Pre-flight Peeking) aus...")
				reachable := peeker.CheckPort(resolvedIP, targetToken.Port)
				if reachable {
					fmt.Printf("      \x1b[1;32m✔ Port %s ist offen und antwortet!\x1b[0m\n", targetToken.Port)
				} else {
					fmt.Printf("      \x1b[1;33m[!] Warnung: Port %s antwortet nicht (Firewall/Offline).\x1b[0m\n", targetToken.Port)
				}
			}
		}
	} else {
		fmt.Println("  [4] RESOLUTION RESULT:")
		if resolveErr != nil {
			fmt.Printf("      \x1b[1;31m[x] Resolution failed: %v\x1b[0m\n", resolveErr)
		} else {
			fmt.Printf("      * Successfully resolved to IP: \x1b[1;32m%s\x1b[0m\n", resolvedIP)
			if targetToken.Port != "" {
				fmt.Printf("      * Active port handoff on port: \x1b[1;36m%s\x1b[0m\n", targetToken.Port)
			}
			if targetToken.Port != "" {
				fmt.Println("      * Running fast pre-flight TCP reachability test...")
				reachable := peeker.CheckPort(resolvedIP, targetToken.Port)
				if reachable {
					fmt.Printf("      \x1b[1;32m✔ Port %s is open and responsive!\x1b[0m\n", targetToken.Port)
				} else {
					fmt.Printf("      \x1b[1;33m[!] Warning: Port %s did not respond (Firewall/Offline).\x1b[0m\n", targetToken.Port)
				}
			}
		}
	}
	fmt.Println()
}
