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
					"  Um IP-Adressen nicht manuell ermitteln zu müssen, stellst du deinem",
					"  Befehl einfach 'vane' voran und nutzt die dynamische Notation.",
					"",
					"  💡 BEDIENUNGSBEISPIEL:",
					"    vane ssh admin@\"eno1|>...gw\"",
					"    --> ssh admin@192.168.178.1",
					"",
					"  🔍 ANATOMIE EINES TOKENS:",
					"    [Interface]  [Operator]  [Punkte]  [Host-Teil]  [Port]",
					"       eno1          |>         ...         gw       :22",
					"",
					"  🔥 AUTOMATISCHES PORT-MAPPING:",
					"    Wird ein Port angegeben (z. B. 'eno1|>...gw:2222') bei ssh/scp, formatiert",
					"    Vane diesen automatisch in die passende Flag des Zielbefehls um (-p bzw. -P).",
				},
			},
			{
				Title: "🌐 2. Die Subnetz-Notation (|>)",
				Content: []string{
					"  Der Operator '|>' referenziert das lokale Subnetz der Netzwerkschnittstelle",
					"  (bevorzugt IPv6 ULA mit automatischem Fallback auf IPv4).",
					"",
					"  📌 STANDARD-GATEWAY AUFLÖSEN (...gw):",
					"    Löst die IP des Standard-Gateways auf dem Interface auf.",
					"    Beispiel: eno1|>...gw  -->  192.168.178.1",
					"",
					"  📌 OKTETTE / SEGMENTE ÜBERSCHREIBEN (...wert):",
					"    Ersetzt die letzten Segmente der eigenen IPv4- oder IPv6-ULA-Adresse.",
					"    Beispiel IPv4 (Eigene IP: 192.168.178.53): eno1|>...33 --> 192.168.178.33",
					"    Beispiel IPv6 (Eigene IP: fd00::...:3e8e): eno1|>...3a8b --> fd00::...:3a8b",
					"",
					"  📌 AUTOMATISCHES MAC-MATCHING (|>...mac):",
					"    Scannt die Kernel-ARP-Tabelle des Betriebssystems in Echtzeit, um das",
					"    fremde Gerät im Subnetz über das Ende seiner MAC-Adresse aufzulösen.",
					"    Beispiel (ARP-Auflösung zu IPv4): eno1|>...cf46  -->  192.168.178.35",
					"",
					"  📌 INTELLIGENTE SCHUTZGRENZE (> 255):",
					"    Eingaben größer als 255 oder Hex-Zeichen werden automatisch als MAC-Endungen",
					"    interpretiert, um eine fehlerhafte IP-Generierung im LAN zu verhindern.",
					"",
					"  📌 LOCALHOST & LOOPBACK (|:):",
					"    Operiert im geschlossenen Loopback-Interface (:1 oder 127.0.0.x).",
					"    Beispiel: 0|:...1  -->  ::1",
					"",
					"  📌 APIPA WARNHINWEIS & SCHUTZ (|!):",
					"    Der Operator '!' dient als visueller Alarm. Er signalisiert in den Listen",
					"    sofort grellgelb: \"HALT! DHCP-Fehler (169.254.x.x) auf dieser Schnittstelle!\"",
					"    Vane blockiert im APIPA-Zustand Befehle automatisch, um Zeitverschwendung zu verhindern.",
				},
			},
			{
				Title: "🔒 3. Die WAN-Notation (|<)",
				Content: []string{
					"  Der Operator '|<' dient dem Auslesen globaler WAN-Verbindungsdaten.",
					"",
					"  📌 EXTERNE WAN-NOTATION (|< ohne Host-Part):",
					"    Gibt die globale IPv6-Adresse (GUA) der Schnittstelle aus, um direkte",
					"    Verbindungen nach außen zu ermöglichen.",
				},
			},
			{
				Title: "🛠️ 4. Integrierte Standalone-Werkzeuge",
				Content: []string{
					"  Zusätzlich zur Token-Ersetzung beinhaltet Vane eigenständige,",
					"  performante Diagnosewerkzeuge ohne externe Abhängigkeiten:",
					"",
					"  📌 SUBNET SCANNER (vane scan [interface]):",
					"    Ein schneller, paralleler TCP-Sweep mit visueller Fortschrittsanzeige.",
					"    Erfasst aktive Systeme und generiert direkt nutzbare Vane-Token.",
					"",
					"  📌 LAUZEIT- & ROUTENANALYSE (vane trace <ziel>):",
					"    Ein interaktiver MTR-ähnlicher Routenprofiler mit Echtzeit-ASCII-Verlaufsgrafiken.",
					"",
					"  📌 HTTP & DNS TRAFFIC SNIFFER (vane sniff [interface]):",
					"    Analysiert unverschlüsselte Anfragen in Echtzeit und bietet eine adaptive Standby-Anzeige.",
					"",
					"  📌 ENCRYPTER P2P FILE-TRANSFER (vane send / vane recv):",
					"    Direkte, gesicherte Dateiübertragung über TLS 1.3 mittels sitzungsgebundener Einmalcodes.",
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
				"  💡 USAGE EXAMPLE:",
				"    vane ssh admin@\"eno1|>...gw\"",
				"    --> ssh admin@192.168.178.1",
				"",
				"  🔍 ANATOMY OF A TOKEN:",
				"    [Interface]  [Operator]  [Punkte]  [Host-Part]  [Port]",
				"       eno1          |>         ...         gw       :22",
				"",
				"  🔥 AUTOMATIC PORT MAPPING:",
				"    If you specify a port (e.g., 'eno1|>...gw:2222') for ssh/scp, Vane",
				"    automatically maps it to the correct flag ('-p 2222' / '-P 2222').",
			},
		},

		{
			Title: "🌐 2. Subnet Notation (|>)",
			Content: []string{
				"  The arrow symbol '|>' references the local LAN subnet configured",
				"  on the specified network interface (preferring IPv6 ULA with automatic IPv4 fallback).",
				"",
				"  📌 DEFAULT GATEWAY (...gw):",
				"    Resolves the IP of the default gateway.",
				"    Example: eno1|>...gw  -->  192.168.178.1",
				"",
				"  📌 OVERRIDE OCTETS / SEGMENTS (...value):",
				"    Replaces the last segment of your own IPv4 or IPv6 ULA address.",
				"    Example IPv4 (Your IP: 192.168.178.53): eno1|>...33 --> 192.168.178.33",
				"    Example IPv6 (Your IP: fd00::...:3e8e): eno1|>...3a8b --> fd00::...:3a8b",
				"",
				"  📌 AUTOMATIC MAC-MATCHING (|>...mac):",
				"    Scans the operating system kernel ARP table in real-time to resolve the",
				"    subnet device matching the specified MAC suffix.",
				"    Example (ARP resolution to IPv4): eno1|>...cf46  -->  192.168.178.35",
				"",
				"  📌 INTUITIVE OCTET SAFEGUARD (> 255):",
				"    Values larger than 255 or hex sequences are automatically classified as MAC",
				"    suffixes to prevent invalid IPv4 constructions within the LAN.",
				"",
				"  📌 LOCALHOST & LOOPBACK (|:):",
				"    Operates within the local loopback interface (:1 or 127.0.0.x).",
				"    Example: 0|:...1  -->  ::1",
				"",
				"  📌 APIPA WARNING & PROTECTION (|!):",
				"    The '!' operator serves as a visual alarm. In interface listings, it highlights",
				"    failures in bright yellow: \"HALT! DHCP Lease Failure (169.254.x.x) on this card!\"",
				"    Vane automatically blocks outbound commands on APIPA interfaces to prevent wasted time.",
			},
		},
		{
			Title: "🔒 3. WAN Notation (|<)",
			Content: []string{
				"  The filter symbol '|<' extracts global WAN addresses for outbound connectivity.",
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
