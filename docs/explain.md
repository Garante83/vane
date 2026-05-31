# Vane Explain Subcommand

> [!NOTE]
> **Availability:** Introduced in Vane **v1.1.0 (Production / Current Feature Branch)** | VSSD Suite

The `vane explain` command is Vane's dedicated **interactive diagnostics and dry-run engine**. It is designed to demystify the Unified IP Notation (UIP) resolution process for administrators and developers by providing a step-by-step audit trail of how any notation resolves to a physical IP and port.

---

## 1. What does `vane explain` do?

When you pass a UIP notation to the command:
```bash
vane explain "eno1|>...pve:8006"
```
Instead of executing a native command, Vane performs a **stealthy dry-run** and prints a visual explanation breakdown in four sequential steps:

1. **Token Extraction:** Shows the parsed segments (Interface, Direction Operator, Dots/Masking depth, Target Host, and Port).
2. **Network Interface Analysis:** Inspects the current bound IP addresses (IPv4, IPv6 ULA, IPv6 GUA) and physical MAC of the target interface.
3. **Dual-Stack Decision Logic:** Outlines which IP stack is prioritized (e.g. preferred IPv6 ULA vs. IPv4 fallback) and why.
4. **Resolution Result & Pre-Flight TCP Probe:** Shows the final resolved IP address and, if a port is present, runs a safe, lightweight TCP reachability check (pre-flight peeking) to verify if the service is online.

---

## 2. Dynamic Shorthand Parsing

To make diagnostics as fast as possible, `vane explain` does not require you to write out the full, strict UIP notation. It features a smart **shorthand translator** that expands loose human input into fully qualified tokens:

| Human Input | Expanded Token | Resolution Strategy |
| :--- | :--- | :--- |
| `lan.1` | `lan|>...1` | Resolves target `.1` on the default LAN interface. |
| `wlan..23` | `wlan|>..23` | Resolves target `.23` with 2-segment subnet masking depth. |
| `1` | `lo|:1` | Detected loopback value → loopback operator (`:`). |
| `pve` | `<active_iface>|>...pve` | Dynamic VSSD semantic service lookup on active interface. |

This means you can simply run:
```bash
vane explain lan.200
```
And Vane will translate it behind the scenes to `lan|>...200`, compile the active interface properties, and verify the path!

---

## 3. Step-by-Step Resolution Example

Below is an example output of `vane explain pve` running in a dual-stack home network segment:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│  vane explain ─ Detaillierte Notations-Analyse (Eingabe: pve)                │
└──────────────────────────────────────────────────────────────────────────────┘
  [+] Extrahierter Token: eno1|>...pve
      - Interface: eno1
      - Richtung:  > (Ausgehendes LAN Segment)
      - Maskierung: 3 Punkt(e) (Subnetzmasken-Tiefe)
      - Ziel-Host:  pve

  [1] SCHNITTSTELLEN-ANALYSE:
      * Physikalische Schnittstelle:   eno1
      * IPv4-Adresse (Lokal):          192.168.178.55
      * IPv6-ULA (Lokal):              fd00::dead:beef:1
      * Hardware-MAC-Adresse:          52:54:00:12:34:56

  [2] DUAL-STACK ENTSCHEIDUNG:
      * Aktive IPv6-ULA (fd00::/8) auf der Schnittstelle gefunden!
      ➔ Bevorzugte Auflösung über IPv6 wird eingeleitet.
      * (IPv4-Fallback wird in Bereitschaft gehalten...)

  [3] UIP BERECHNUNG (IPv6 ULA):
      * Segment-Ersetzung: Überschreibe Host-Teil mit 'pve'
      * IPv6-Präfix-Basis: fd00::

  [4] ZIELAUFLÖSUNG:
      * Erfolgreich aufgelöst zu IP:  fd00::bc24:11ff:fe00:200
      * Port-Handoff aktiv für Port:  8006
      * Führe schnellen TCP-Erreichbarkeitstest (Pre-flight Peeking) aus...
      ✔ Port 8006 ist offen und antwortet!
```

---

## 4. Key Diagnostic Use Cases

### A. Troubleshooting Cache Issues (VSSD Debugging)
If a semantic token (like `...pve` or `...nas`) is not resolving as expected, running `explain` will tell you if the token is resolved via active mDNS, the local static VSSD cache (`cache.json`), or if the resolution failed:
```bash
vane explain pve
# Output Step [3] will show: "Querying local VSSD cache registry..."
```

### B. Dual-Stack Validation
If you are unsure whether your local segment has a valid IPv6 Unique Local Address (ULA) configuration, `explain` instantly maps the local interface's dual-stack priorities and visualizes if the connection will go over IPv6 or fall back to IPv4.

### C. Firewall Verification (Pre-Flight Probing)
Because `explain` runs a safe TCP handshake when a port is specified in the token (e.g. `eno1|>...pve:8006`), you can verify if a firewall or local service is blocked/offline before you run complex network operations:
```bash
vane explain pve:8006
# Will output either "Port is open" or a warning "Port did not respond (Firewall/Offline)"
```
