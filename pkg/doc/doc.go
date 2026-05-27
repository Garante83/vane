package doc

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Page holds the manual page content
type Page struct {
	Title   string
	Content []string
}

// GetPages returns the document pages based on the system language
func GetPages(lang string) []Page {
	if lang == "de" {
		return []Page{
			{
				Title: "🚀 1. Das Kernkonzept & Handoff",
				Content: []string{
					"  Vane ist ein intelligenter, abhängigkeitsfreier Shell-Proxy-Wrapper.",
					"  Anstatt IPs manuell nachzuschlagen oder abzutippen, setzt du einfach 'vane'",
					"  vor deinen Befehl und verwendest unsere dynamische Notation.",
					"",
					"  Vane übersetzt die Variablen-Token in Millisekunden in echte IP-Adressen",
					"  und übergibt die Ausführung nahtlos zurück an das System (Kernel Handoff).",
					"",
					"  💡 BEDIENUNGSBEISPIEL:",
					"    vane ssh admin@\"eno1|>...gw\"",
					"",
					"    Wird im Hintergrund automatisch übersetzt und ausgeführt als:",
					"    ssh admin@192.168.178.1  (wenn 192.168.178.1 dein Default Gateway ist)",
					"",
					"  🔥 AUTOMATISCHES PORT-MAPPING:",
					"    Wenn du bei ssh oder scp einen Port anhängst (z. B. 'eno1|>...gw:2222'),",
					"    übersetzt Vane dies automatisch in die korrekte Flag ('-p 2222' / '-P 2222').",
				},
			},
			{
				Title: "🌐 2. Die Subnetz-Notation (|>)",
				Content: []string{
					"  Mit dem Pfeil-Symbol '|>' greifst du auf das lokale LAN-Subnetz des",
					"  Interfaces zu (basierend auf der dort konfigurierten IP/Subnetzmaske).",
					"",
					"  📌 STANDARD-GATEWAY AUFLÖSEN (...gw):",
					"    Löst die IP des Standard-Gateways auf dem Interface auf.",
					"    Beispiel: eno1|>...gw  -->  192.168.178.1",
					"",
					"  📌 EINZELNE OKTETTE ÜBERSCHREIBEN (...wert):",
					"    Ersetzt das letzte Segment deiner eigenen IP mit dem angegebenen Wert.",
					"    Beispiel (Eigene IP: 192.168.178.53):",
					"    eno1|>...33  -->  192.168.178.33",
					"",
					"  📌 MEHRERE OKTETTE ÜBERSCHREIBEN (..wert.wert):",
					"    Ersetzt die hinteren 2 oder 3 Segmente deiner eigenen IP.",
					"    Beispiel: eno1|>..100.33  -->  192.168.100.33",
					"",
					"  📌 DUAL-STACK (IPv6 ULA):",
					"    Funktioniert absolut identisch für lokale IPv6-ULA-Netze!",
				},
			},
			{
				Title: "🔒 3. MAC-Matching & WAN-Notation (|<)",
				Content: []string{
					"  Mit dem Trichter-Symbol '|<' filterst du nach globalen Adressen oder",
					"  spürst Geräte anhand ihrer Hardware-Adresse (MAC) auf.",
					"",
					"  📌 AUTOMATISCHES MAC-MATCHING (|<...mac):",
					"    Vane spürt ein Gerät im lokalen Subnetz anhand der letzten Zeichen seiner",
					"    MAC-Adresse oder EUI-64 auf. Es gleicht die ARP-Tabelle im Kernel ab.",
					"    Beispiel: eno1|<...3e8e  -->  192.168.178.53",
					"",
					"  📌 INTELLIGENTE SCHUTZGRENZE (> 255):",
					"    Werte größer als 255 werden von Vane automatisch als hexadezimale MAC-Suffixe",
					"    klassifiziert (z. B. '300' oder 'a1b2'), um Fehlkonfigurationen zu vermeiden.",
					"",
					"  📌 EXTERNE WAN-NOTATION (|< ohne Host-Part):",
					"    Ermittelt die globale IPv6-Adresse (GUA) auf dem Interface für sichere",
					"    Verbindungen nach außen.",
				},
			},
			{
				Title: "🛠️ 4. Integrierte Standalone-Werkzeuge",
				Content: []string{
					"  Neben der Proxy-Ersetzung bringt Vane nützliche, hochperformante und",
					"  vollkommen abhängigkeitsfreie Diagnosewerkzeuge mit:",
					"",
					"  📌 SUBNET SCANNER (vane scan [interface]):",
					"    Ein extrem schneller, paralleler TCP-Sweep mit Live-Fortschritts-Spinner.",
					"    Zeigt alle aktiven Hosts und schlägt fertige Vane-Token zum Kopieren vor.",
					"",
					"  📌 LAUZEIT- & ROUTENANALYSE (vane trace <ziel>):",
					"    Ein interaktiver MTR-style Routenprofiler mit Live-ASCII-Sparklines.",
					"",
					"  📌 HTTP & DNS TRAFFIC SNIFFER (vane sniff [interface]):",
					"    Liest unverschlüsselte Anfragen live mit. Mit intelligentem Standby-Spinner.",
					"",
					"  📌 ENCRYPTER P2P FILE-TRANSFER (vane send / vane recv):",
					"    Verschlüsselte Direktübertragungen via TLS 1.3 und sessiongebundenen Codes.",
				},
			},
		}
	}

	// Default to English manual
	return []Page{
		{
			Title: "🚀 1. Core Concept & Proxy Handoff",
			Content: []string{
				"  Vane is a smart, zero-dependency shell proxy wrapper.",
				"  Instead of looking up IPs manually, you prefix 'vane' to your",
				"  command and use our dynamic notation.",
				"",
				"  Vane translates the token in milliseconds to active IPs and",
				"  hands execution directly back to the operating system (Kernel Handoff).",
				"",
				"  💡 USAGE EXAMPLE:",
				"    vane ssh admin@\"eno1|>...gw\"",
				"",
				"    Will automatically resolve and run in the background as:",
				"    ssh admin@192.168.178.1  (assuming 192.168.178.1 is your default gateway)",
				"",
				"  🔥 AUTOMATIC PORT MAPPING:",
				"    If you specify a port (e.g., 'eno1|>...gw:2222') for ssh or scp,",
				"    Vane automatically maps it to the correct flag ('-p 2222' / '-P 2222').",
			},
		},
		{
			Title: "🌐 2. Subnet Notation (|>)",
			Content: []string{
				"  The arrow symbol '|>' references the local LAN subnet configured",
				"  on the specified network interface.",
				"",
				"  📌 DEFAULT GATEWAY (...gw):",
				"    Resolves the IP of the default gateway.",
				"    Example: eno1|>...gw  -->  192.168.178.1",
				"",
				"  📌 OVERRIDE SINGLE OCTET (...value):",
				"    Replaces the last segment of your own IP.",
				"    Example (Your IP: 192.168.178.53):",
				"    eno1|>...33  -->  192.168.178.33",
				"",
				"  📌 OVERRIDE MULTIPLE OCTETS (..value.value):",
				"    Replaces the last 2 or 3 segments of your IP.",
				"    Example: eno1|>..100.33  -->  192.168.100.33",
				"",
				"  📌 DUAL-STACK (IPv6 ULA):",
				"    Works exactly the same way for local IPv6 Unique Local Addresses!",
			},
		},
		{
			Title: "🔒 3. MAC-Matching & WAN Notation (|<)",
			Content: []string{
				"  The filter symbol '|<' extracts global WAN addresses or locates",
				"  devices based on hardware MAC/EUI-64 addresses.",
				"",
				"  📌 AUTOMATIC MAC-MATCHING (|<...mac):",
				"    Vane scans the kernel ARP table to map the specified suffix to the",
				"    active local IP of that device.",
				"    Example: eno1|<...3e8e  -->  192.168.178.53",
				"",
				"  📌 INTUITIVE OCTET SAFEGUARD (> 255):",
				"    Values larger than 255 are automatically classified as MAC hex suffixes",
				"    (e.g., '300' or 'a1b2') to prevent invalid IPv4 constructions.",
				"",
				"  📌 EXTERNAL WAN ADDRESS (|< without host suffix):",
				"    Resolves the global IPv6 address (GUA) on the interface for safe",
				"    outbound connectivity.",
			},
		},
		{
			Title: "🛠️ 4. Integrated Companion Utilities",
			Content: []string{
				"  Alongside command substitution, Vane packs zero-dependency",
				"  high-performance utility commands:",
				"",
				"  📌 SUBNET SCANNER (vane scan [interface]):",
				"    Ultra-fast concurrent port sweeper with real-time progress indicator.",
				"    Finds active hosts and outputs ready-to-copy Vane tokens.",
				"",
				"  📌 INTERACTIVE ROUTE PROFILER (vane trace <target>):",
				"    Interactive MTR-style path tracer with live ASCII sparklines.",
				"",
				"  📌 PACKET SNIFFER (vane sniff [interface]):",
				"    Monitors live HTTP & DNS requests on the wire with standby spinners.",
				"",
				"  📌 P2P FILE-TRANSFER (vane send / vane recv):",
				"    Encrypted high-performance peer-to-peer file transfers using TLS 1.3.",
			},
		},
	}
}

// ShowManual opens the interactive terminal manual
func ShowManual(lang string) {
	pages := GetPages(lang)
	currPage := 0

	// Clear helper
	clearScreen := func() {
		fmt.Print("\x1b[H\x1b[2J")
	}

	render := func(pageIdx int) {
		clearScreen()
		page := pages[pageIdx]

		printHeaderLine := func(text string) {
			runes := []rune(text)
			padding := 74 - len(runes)
			if padding < 0 {
				padding = 0
			}
			fmt.Print("  │" + text + strings.Repeat(" ", padding) + "│\r\n")
		}

		// Draw gorgeous header (indented 2 spaces, inside width 74 characters)
		fmt.Print("  ┌" + strings.Repeat("─", 74) + "┐\r\n")
		if lang == "de" {
			printHeaderLine("  vane ─ Interaktives Handbuch / System-Dokumentation")
		} else {
			printHeaderLine("  vane ─ Interactive Terminal Manual & System Documentation")
		}
		fmt.Print("  ├" + strings.Repeat("─", 74) + "┤\r\n")
		
		// Page bar: Center the items beautifully inside the box
		var navs []string
		labels := []string{"Konzept", "Subnetz", "MAC / WAN", "Werkzeuge"}
		if lang != "de" {
			labels = []string{"Concept", "Subnet", "MAC / WAN", "Utilities"}
		}

		for i := 0; i < len(pages); i++ {
			activeIndicator := " "
			if i == pageIdx {
				activeIndicator = "*"
			}
			navs = append(navs, fmt.Sprintf("[%d%s] %s", i+1, activeIndicator, labels[i]))
		}
		navStr := strings.Join(navs, "    ") // 4 spaces between items
		
		// Center the navigation string inside the 74-character width
		totalInsideWidth := 74
		navLen := len([]rune(navStr))
		leftPadding := (totalInsideWidth - navLen) / 2
		rightPadding := totalInsideWidth - navLen - leftPadding
		fmt.Print("  │" + strings.Repeat(" ", leftPadding) + navStr + strings.Repeat(" ", rightPadding) + "│\r\n")

		fmt.Print("  └" + strings.Repeat("─", 74) + "┘\r\n")
		fmt.Print("\r\n")

		// Title: indented exactly 4 spaces (matching inner text margin of the box!)
		fmt.Printf("    \033[1;36m%s\033[0m\r\n", page.Title)
		fmt.Print("    " + strings.Repeat("═", len([]rune(page.Title))-2) + "\r\n") // Dynamic underline based on runes
		fmt.Print("\r\n")

		// Render Content: perfectly aligned to the exact same 4-space left margin
		for _, line := range page.Content {
			trimmed := strings.TrimPrefix(line, "  ")
			fmt.Print("    " + trimmed + "\r\n")
		}

		// Fill lines to keep footer height consistent
		paddingLines := 17 - len(page.Content)
		for i := 0; i < paddingLines; i++ {
			fmt.Print("\r\n")
		}

		// Navigation Footer: aligned border at 2 spaces, help text at 4 spaces
		fmt.Print("  " + strings.Repeat("─", 74) + "\r\n")
		if lang == "de" {
			fmt.Print("    [1-4]: Seite springen  |  [j/Leertaste]: Vor  |  [k]: Zurück  |  [q]: Beenden\r\n")
		} else {
			fmt.Print("    [1-4]: Jump to page  |  [j/Space]: Next  |  [k]: Back  |  [q/Esc]: Exit Manual\r\n")
		}
	}

	// Try to use Unix Raw Mode for single-keypress navigation
	restore, err := setRawMode()
	if err == nil {
		defer restore()
		render(currPage)

		buf := make([]byte, 3)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				break
			}

			if n > 0 {
				key := buf[0]

				// Exit keys
				if key == 'q' || key == 'Q' || key == 3 || key == 27 { // q, Q, Ctrl+C, Esc
					clearScreen()
					break
				}

				// Page shortcuts
				if key >= '1' && key <= '4' {
					currPage = int(key - '1')
					render(currPage)
					continue
				}

				// Next page keys: 'j', 'J', Space, or ArrowDown (which starts with ESC [ B)
				isNext := key == 'j' || key == 'J' || key == ' '
				if n >= 3 && buf[0] == 27 && buf[1] == '[' && buf[2] == 'B' { // ArrowDown
					isNext = true
				}
				if isNext {
					currPage = (currPage + 1) % len(pages)
					render(currPage)
					continue
				}

				// Previous page keys: 'k', 'K', or ArrowUp (ESC [ A)
				isPrev := key == 'k' || key == 'K'
				if n >= 3 && buf[0] == 27 && buf[1] == '[' && buf[2] == 'A' { // ArrowUp
					isPrev = true
				}
				if isPrev {
					currPage = (currPage - 1 + len(pages)) % len(pages)
					render(currPage)
					continue
				}
			}
		}
		return
	}

	// Fallback Mode (Windows / Non-TTY / No stty available)
	reader := bufio.NewReader(os.Stdin)
	for {
		render(currPage)
		fmt.Print("\r\n")
		if lang == "de" {
			fmt.Print("  Wähle eine Seite (1-4) oder 'q' zum Beenden: ")
		} else {
			fmt.Print("  Select a page (1-4) or 'q' to quit: ")
		}

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		input = strings.TrimSpace(strings.ToLower(input))
		if input == "q" || input == "quit" || input == "exit" {
			clearScreen()
			break
		}

		if len(input) > 0 {
			char := input[0]
			if char >= '1' && char <= '4' {
				currPage = int(char - '1')
			}
		}
	}
}

// setRawMode puts the terminal in raw mode using 'stty'
func setRawMode() (func(), error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("raw mode not supported natively on windows")
	}

	// Get current stty settings
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	state, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Switch to raw mode, disabling echo and buffering
	cmdRaw := exec.Command("stty", "raw", "-echo")
	cmdRaw.Stdin = os.Stdin
	err = cmdRaw.Run()
	if err != nil {
		return nil, err
	}

	// Return restore callback
	return func() {
		cmdRestore := exec.Command("stty", strings.TrimSpace(string(state)))
		cmdRestore.Stdin = os.Stdin
		_ = cmdRestore.Run()
	}, nil
}
