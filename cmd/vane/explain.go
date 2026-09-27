package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"vane/pkg/netstate"
	"vane/pkg/peeker"
	"vane/pkg/uip"
	"vane/pkg/util"
)

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
	lang := util.GetSystemLanguage()

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
