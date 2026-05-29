# Unified IP Notation (UIP): Advanced Resolving & Edge-Cases

This document details the advanced inner workings of Vane's Unified IP Notation (UIP) engine. It is written for network administrators and developers who need to understand how the parser translates shorthand tokens into raw, validated network addresses under complex dual-stack routing environments and failure states.

---

## 1. The Address Resolution Decision Tree

When Vane receives a UIP token (e.g., `eno1|>...33`), it queries the system network state using the `netstate` package and processes the token through a strict, deterministic resolution tree:

```
                  [Input UIP Token]
                         │
           ┌─────────────┴─────────────┐
     Direction Modifer?                │
  ┌────────┼─────────────┼─────────────┼────────┐
  ▼        ▼             ▼             ▼        ▼
 [>]      [<]           [:]           [!]      [?]
 LAN      WAN         Loopback       APIPA    Error
```

---

## 2. Advanced Direction Modifiers

### A. The Outbound LAN Modifier (`>`)
The `>` modifier targets the local network segment. It prioritizes IPv6 Unique Local Addresses (ULA) for security and modern dual-stack compliance, falling back automatically to IPv4:

1.  **IPv6 ULA Priority:**
    If the interface has a valid IPv6 ULA configured (in the `fd00::/8` range), Vane resolves the token using IPv6.
    *   *Gateway:* `eno1|>...gw` resolves to the local IPv6 gateway.
    *   *Host Part:* `eno1|>...3e8e` injects the hex segment into the ULA prefix.
2.  **IPv4 Fallback:**
    If no IPv6 ULA is present, Vane falls back to standard IPv4 dot-segment notation (`ResolveIPv4Dots`).
3.  **Global Unicast (GUA) Fallback:**
    If no ULA or IPv4 address is present, Vane will attempt to resolve using the interface's Global IPv6 prefix as an extreme fallback.

---

### B. The External WAN Modifier (`<`)
The `<` modifier represents global internet and external WAN routing. It operates strictly under **IPv6 Global Unicast Address (GUA)** scopes (prefixes starting with `2000::`):

*   **MAC/EUI-64 Injection:** 
    Passing `0` as the host part (e.g. `eno1|<...0`) automatically extracts your interface's physical MAC address, calculates its EUI-64 SLAAC suffix, and builds your global IPv6 address.
*   **Hybrid Prefixing:** 
    Extracts the `/64` WAN routing prefix of your active gateway and injects custom host values into the interface.

---

### C. The Loopback Modifier (`:`)
The `:` modifier is dedicated to local host diagnostics and loopback routing:

*   **IPv6 Loopback:** 
    Setting the host part to `1` (e.g. `lo|:1`) instantly resolves to the standard IPv6 loopback:
    ```
    ::1
    ```
*   **IPv4 Loopback overrides:**
    Otherwise, Vane parses the loopback context using standard dot notation overrides on the local loopback segment (defaulting to `127.0.0.1` or overriding octets relative to the dot depth).

---

### D. The APIPA Emergency Modifier (`!`)
The `!` modifier is an **isolated emergency mode** designed for zero-configuration debugging (when a network has no DHCP server and hosts are isolated):

*   **APIPA Segment Mapping:**
    Resolves targets using the standard Link-Local IPv4 auto-configuration space:
    ```
    169.254.0.0/16
    ```
*   *Example:* `eno1|!...45` instantly maps to the isolated network target `169.254.0.45` to allow emergency pings even if DHCP leasing has completely crashed.

---

## 3. High-Fidelity Edge-Case Safeguards

To prevent confusing errors and silent network failures, Vane's UIP engine contains several defensive guardrails:

### A. Passive DHCP-Fail Detection (APIPA Warnings)
If an interface fails to lease an IP from a DHCP server, operating systems automatically assign themselves an APIPA address (`169.254.X.X`). 

Vane actively intercepts this state during standard LAN resolving (`>`). Instead of attempting a broken connection, Vane throws a hard, highly descriptive alert:
```
[!] vane ─ APIPA erkannt auf eno1 (DHCP-FAIL)
```
This instantly flags to the administrator that the DHCP server or interface lease has failed, saving valuable diagnostic time.

---

### B. Dynamic MAC Suffix Resolution (ARP Lookup)
If you pass a hexadecimal MAC suffix (e.g., `eno1|>...8e02`), Vane performs a secure, cross-platform ARP table inspection:

1.  **Cross-Platform Parsers:** Vane queries `/proc/net/arp` on Linux, or issues a secure PowerShell `Get-NetNeighbor` pipeline on Windows.
2.  **Suffix Matching:** It scans the active system neighbor cache for a hardware MAC ending with your target suffix.
3.  **Silent Resolution:** It extracts the active IPv4 address belonging to that MAC address and resolves it instantly.
4.  *Safety:* If the MAC suffix does not exist in the neighbor cache, Vane throws a clean error instead of issuing noisy network broadcast probes.

---

### C. Greedy Parser Port Correction
UIP uses a highly robust Regular Expression engine. However, hexadecimal MAC addresses and standard TCP/UDP port notation both use colons (`:`), which can cause parsing conflicts (e.g., `eno1|>...3e:8e:2222` where `2222` is the port and `3e:8e` is the suffix).

To solve this, Vane contains a **Greedy Parser Correction Hook**:
*   Vane checks if the trailing segment of a resolved token consists strictly of numerical digits.
*   If so, it dynamically strips that segment from the `HostPart` and correctly re-assigns it to the `Port` token field.
*   This ensures that port-forwarded MAC-addresses resolve flawlessly without requiring escape characters.
