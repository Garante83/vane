package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"vane/pkg/transfer"
	"vane/pkg/uip"
	"vane/pkg/util"
	"vane/pkg/vssd"
)

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

func handleDiscoverSubcommand(ifaceName string, persistent, sweepFlag, clearFlag, editFlag bool, targetIP, targetMAC string, exportFlag bool, importCode string) error {
	// 1.1 Cache Importing Action
	if importCode != "" {
		registryData, err := transfer.PerformRegistryReceive("8484")
		if err != nil {
			return err
		}
		added, demoted, err := vssd.MergeIncomingRegistry(registryData, ifaceName)
		if err != nil {
			return err
		}
		if util.GetSystemLanguage() == "de" {
			fmt.Printf("  \x1b[1;32m✔ Registry erfolgreich synchronisiert! %d Einträge hinzugefügt/aktualisiert, %d Einträge als Konflikt-Alias demotiert.\x1b[0m\n", added, demoted)
		} else {
			fmt.Printf("  \x1b[1;32m✔ Registry successfully synchronized! %d entries added/updated, %d entries demoted as conflict aliases.\x1b[0m\n", added, demoted)
		}
		return nil
	}

	// 1.2 Cache Exporting Action
	if exportFlag {
		localMap, err := vssd.LoadCacheForInterface(ifaceName)
		if err != nil {
			return err
		}
		if len(localMap) == 0 {
			if util.GetSystemLanguage() == "de" {
				return fmt.Errorf("dein lokaler Registry-Cache für Interface %s ist leer. Es gibt nichts zu exportieren", ifaceName)
			}
			return fmt.Errorf("your local registry cache for interface %s is empty. Nothing to export", ifaceName)
		}
		registryData, err := json.Marshal(localMap)
		if err != nil {
			return err
		}

		code := ""
		for i := 2; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--code" || os.Args[i] == "-c" {
				code = os.Args[i+1]
				break
			}
		}
		if code == "" {
			if util.GetSystemLanguage() == "de" {
				return fmt.Errorf("bitte gib den Empfänger-Code an (z. B. vane discover --export --code 192.168.178.50#1234-5678)")
			}
			return fmt.Errorf("please specify the receiver pairing code (e.g. vane discover --export --code 192.168.178.50#1234-5678)")
		}

		return transfer.PerformRegistrySend(registryData, code)
	}

	// 1.3 Cache Clearing Action
	if clearFlag {
		path, err := vssd.GetCachePath()
		if err != nil {
			return err
		}

		// If cache file doesn't exist, tell the user it is already empty
		if _, errStat := os.Stat(path); os.IsNotExist(errStat) {
			if util.GetSystemLanguage() == "de" {
				fmt.Println("  \x1b[1;33m[!] Der Service-Cache ist bereits leer.\x1b[0m")
			} else {
				fmt.Println("  \x1b[1;33m[!] The service cache is already empty.\x1b[0m")
			}
			return nil
		}

		// Ask for confirmation in clean Vane styling
		var response string
		if util.GetSystemLanguage() == "de" {
			fmt.Print("  \x1b[1;33m[?] Möchtest du den Vane-Service-Cache wirklich löschen? [Y/n]:\x1b[0m ")
		} else {
			fmt.Print("  \x1b[1;33m[?] Are you sure you want to clear the Vane service cache? [Y/n]:\x1b[0m ")
		}

		_, _ = fmt.Scanln(&response)
		response = strings.TrimSpace(strings.ToLower(response))

		// Default to Yes if they press Enter (empty response) or input y/yes/ja
		if response == "" || response == "y" || response == "yes" || response == "ja" {
			_ = os.Remove(path)
			if util.GetSystemLanguage() == "de" {
				fmt.Println("  \x1b[1;32m✔ Cache wurde erfolgreich gelöscht!\x1b[0m")
			} else {
				fmt.Println("  \x1b[1;32m✔ Cache cleared successfully!\x1b[0m")
			}
		} else {
			if util.GetSystemLanguage() == "de" {
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
						if util.GetSystemLanguage() == "de" {
							fmt.Printf("\r  %s Führe gezieltes Port-Fingerprinting für %s aus... ☕", spinner[idx], targetIP)
						} else {
							fmt.Printf("\r  %s Running targeted port fingerprinting for %s... ☕", spinner[idx], targetIP)
						}
					} else {
						if util.GetSystemLanguage() == "de" {
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
					if util.GetSystemLanguage() == "de" {
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
	if util.GetSystemLanguage() == "de" {
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
		if util.GetSystemLanguage() == "de" {
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
		if util.GetSystemLanguage() == "de" {
			fmt.Println("\n  \x1b[1;32m✔ Mappings wurden erfolgreich in cache.json gespeichert (chmod 0600)!\x1b[0m")
		} else {
			fmt.Println("\n  \x1b[1;32m✔ Mappings successfully saved to cache.json (chmod 0600)!\x1b[0m")
		}
	} else if sweepFlag || targetIP != "" {
		if util.GetSystemLanguage() == "de" {
			fmt.Println("\n  Tipp: Nutze \"vane discover --persistent\" zum Speichern für lautlose Auflösung!")
		} else {
			fmt.Println("\n  Tip: Use \"vane discover --persistent\" to save mappings for stealthy local resolution!")
		}
	} else {
		if util.GetSystemLanguage() == "de" {
			fmt.Println("\n  Hinweis: Dies zeigt den passiv erkannten Cache-Stand. Nutze \"--sweep\" (-w) für einen aktiven Nachbarschafts-Sweep!")
		} else {
			fmt.Println("\n  Note: This shows the passive cached state. Use \"--sweep\" (-w) to run an active neighborhood sweep!")
		}
	}

	if util.GetSystemLanguage() == "de" {
		fmt.Println("  Tipp: Nutze \"--edit\" (-e) zum händischen Bearbeiten oder \"--clear\" (-c) zum Löschen des Caches.")
	} else {
		fmt.Println("  Tip: Use \"--edit\" (-e) to manually edit or \"--clear\" (-c) to clear the local cache.")
	}

	// Dynamic hint if a corrupted cache backup file exists
	if cachePath, errPath := vssd.GetCachePath(); errPath == nil {
		if _, errStat := os.Stat(cachePath + ".corrupted"); errStat == nil {
			if util.GetSystemLanguage() == "de" {
				fmt.Printf("  \x1b[1;33m[!] Hinweis: Eine beschädigte Cache-Backup-Datei wurde unter '%s.corrupted' gesichert.\x1b[0m\n", cachePath)
			} else {
				fmt.Printf("  \x1b[1;33m[!] Note: A corrupted cache backup file is stored at '%s.corrupted'.\x1b[0m\n", cachePath)
			}
		}
	}
	fmt.Println()

	return nil
}

// getDirectionName returns the human-readable description of a Vane operator
