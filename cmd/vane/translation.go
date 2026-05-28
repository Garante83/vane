package main

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
	HelpDiscover     string
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
	HelpDiscover:     "  vane discover [iface] [flags]   Sucht nach bekannten Services im LAN (Proxmox, NAS, Hass, Pi).",
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
	HelpDiscover:     "  vane discover [iface] [flags]    Discovers known services in the LAN (Proxmox, NAS, Hass, Pi).",
	HelpManual:       "  vane doc / man                  Opens the interactive TUI manual (system documentation).",
	HelpMatrix:       "  vane                             Shows the Local Network Interface Matrix.",
	ConvertULA:       "-> ULA (Internal): %s%s\n",
	ConvertIPv4Equiv: "-> IPv4 Equivalent: %s\n",
	NoIPBound:        "No IP bound",
	ErrorMACMismatch: "[vane] Error: MAC suffix '%s' does not match interface %s.\n",
}

var msg = en
