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
	"time"

	"vane/pkg/netstate"
	"vane/pkg/uip"
	"vane/pkg/vssd"
)

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
		vssd.EnsureCacheOwnership(path)
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
				fmt.Print("    Kürzel / Token (z. B. nas oder pve.2): ")
				tokInput, _ := reader.ReadString('\n')
				tokInput = strings.TrimSpace(strings.ToLower(tokInput))
				if tokInput == "" {
					break
				}

				// Validate: exakt 3 Kleinbuchstaben ODER 5 Zeichen (3 Kleinbuchstaben + '.'/'1-9' oder '-'/'1-9')
				isValid := false
				if len(tokInput) == 3 {
					isValid = true
					for _, r := range tokInput {
						if r < 'a' || r > 'z' {
							isValid = false
							break
						}
					}
				} else if len(tokInput) == 5 {
					isValid = true
					for _, r := range tokInput[:3] {
						if r < 'a' || r > 'z' {
							isValid = false
							break
						}
					}
					if isValid {
						sep := tokInput[3]
						digit := tokInput[4]
						if (sep != '.' && sep != '-') || (digit < '0' || digit > '9') {
							isValid = false
						}
					}
				}

				if !isValid {
					if getSystemLanguage() == "de" {
						fmt.Println("    \x1b[1;31m❌ Fehler: Das Kürzel muss entweder aus exakt 3 Kleinbuchstaben (z. B. nas) oder aus 5 Zeichen (z. B. pve.2 oder pve-2) bestehen!\x1b[0m")
					} else {
						fmt.Println("    \x1b[1;31m❌ Error: Token must be either exactly 3 lowercase letters (e.g. nas) or exactly 5 characters (e.g. pve.2 or pve-2)!\x1b[0m")
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

				// Auto-fill assistant: lookup IP in OS neighbor cache to resolve MAC and IPv6
				if fullMAC, errMAC := lookupMACByIP(ifaceName, ip); errMAC == nil && fullMAC != "" {
					autoMAC = fullMAC
					if hwAddr, errHW := net.ParseMAC(fullMAC); errHW == nil {
						eui := uip.ComputeEUI64(hwAddr)
						if eui != "" {
							autoIPv6 = "fe80::" + eui
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
				fmt.Printf("    Kürzel / Token [\x1b[90m%s\x1b[0m] (z. B. nas oder pve.2): ", tok)
				tokInput, _ := reader.ReadString('\n')
				tokInput = strings.TrimSpace(strings.ToLower(tokInput))
				if tokInput == "" || tokInput == tok {
					newTok = tok
					break
				}

				// Validate: exakt 3 Kleinbuchstaben ODER 5 Zeichen (3 Kleinbuchstaben + '.'/'1-9' oder '-'/'1-9')
				isValid := false
				if len(tokInput) == 3 {
					isValid = true
					for _, r := range tokInput {
						if r < 'a' || r > 'z' {
							isValid = false
							break
						}
					}
				} else if len(tokInput) == 5 {
					isValid = true
					for _, r := range tokInput[:3] {
						if r < 'a' || r > 'z' {
							isValid = false
							break
						}
					}
					if isValid {
						sep := tokInput[3]
						digit := tokInput[4]
						if (sep != '.' && sep != '-') || (digit < '0' || digit > '9') {
							isValid = false
						}
					}
				}

				if !isValid {
					if getSystemLanguage() == "de" {
						fmt.Println("    \x1b[1;31m❌ Fehler: Das Kürzel muss entweder aus exakt 3 Kleinbuchstaben (z. B. nas) oder aus 5 Zeichen (z. B. pve.2 oder pve-2) bestehen!\x1b[0m")
					} else {
						fmt.Println("    \x1b[1;31m❌ Error: Token must be either exactly 3 lowercase letters (e.g. nas) or exactly 5 characters (e.g. pve.2 or pve-2)!\x1b[0m")
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

				// Auto-fill assistant during edit: lookup IP in OS neighbor cache to resolve MAC and IPv6
				if fullMAC, errMAC := lookupMACByIP(ifaceName, entry.IP); errMAC == nil && fullMAC != "" {
					entry.MAC = fullMAC
					if hwAddr, errHW := net.ParseMAC(fullMAC); errHW == nil {
						eui := uip.ComputeEUI64(hwAddr)
						if eui != "" {
							entry.IPv6 = "fe80::" + eui
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
		vssd.EnsureCacheOwnership(path)
	}
}

func validateAndResolveIPInput(input, ifaceName string) (string, error) {
	input = strings.Trim(strings.TrimSpace(input), "\"'")
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

func lookupMACByIP(ifaceName, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetNeighbor -InterfaceAlias '%s' -IPAddress '%s' | Select-Object -ExpandProperty LinkLayerAddress", ifaceName, ip))
		out, err := cmd.Output()
		if err == nil {
			mac := strings.TrimSpace(string(out))
			mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
			if mac != "" && len(mac) >= 12 {
				return mac, nil
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
		entryIP := fields[0]
		mac := strings.ToLower(fields[3])
		dev := fields[5]

		if dev == ifaceName && entryIP == ip {
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac, nil
			}
		}
	}
	return "", fmt.Errorf("not found")
}
