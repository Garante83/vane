# Universal IP (UIP) & Vane Notation

The Universal IP (UIP) parser is one of Vane's most innovative features. It allows system administrators and homelab enthusiasts to reference network hosts using dynamic, shorthand tokens instead of static, hard-to-remember IPv4 or IPv6 addresses. 

This guide explains the syntax, underlying mathematics, and EUI-64 autoconfiguration rules that drive the UIP engine.

---

## 1. The UIP Token Syntax

A Vane notation token is structured as a readable string that binds a physical network interface to a target host address using a specific modifier:

```
[Interface]|[Modifier][Value]
```

### Anatomy of a Token
*   **Interface (e.g. `eno1`):** The local network interface through which communication is routed.
*   **Delimiter (`|`):** Separates the interface context from the host.
*   **Modifier (`>` or `:`):** Defines the resolution scope.
    *   `>` indicates a local subnet or network-adjacent target.
    *   `:` indicates a loopback mapping.
*   **Value (e.g. `...33` or `...gw`):** The host-specific target identifier.

---

## 2. IPv4 Resolution Rules (Dot Notation)

In dynamic dual-stack subnets, the prefix of a local network (e.g., `192.168.178.X`) is usually shared by all devices. UIP takes advantage of this by allowing you to specify only the host octets.

### Host Suffix Replacement
Vane dynamically reads the IP address configuration of your local interface and prepends the matching prefix onto your shorthand value:

*   **3-Dot Notation (`...33`):** Replaces the last octet.
    *   *Local IP:* `192.168.178.10`
    *   *Token:* `eno1|>...33`
    *   *Resolved IP:* `192.168.178.33`
*   **2-Dot Notation (`..10.5`):** Replaces the last two octets (ideal for wider `/16` networks or custom VLAN segments).
    *   *Local IP:* `10.0.50.144`
    *   *Token:* `eno1|>..10.5`
    *   *Resolved IP:* `10.0.10.5`

### Gateway Shorthand
To quickly contact your router or default gateway without looking up your routing tables, you can use the `gw` keyword:
*   *Token:* `eno1|>...gw`
*   *Resolved IP:* Automatically resolves to the interface's current default gateway IP (e.g., `192.168.178.1`).

---

## 3. IPv6 Link-Local & EUI-64 Autoconfiguration

IPv6 Link-Local addresses (starting with `fe80::`) can be exceptionally tedious to type manually. Vane solves this by automatically calculating host SLAAC addresses from MAC addresses using the IEEE EUI-64 standard.

### The EUI-64 Conversion Process
When you register a custom service MAC address (e.g., in the cache editor via `vane discover -e`), Vane automatically computes its Link-Local IPv6 address under the hood:

1.  **MAC Address Split:** The 48-bit MAC address (e.g., `00:11:32:3E:8E:02`) is split into two 24-bit halves: `00:11:32` and `3E:8E:02`.
2.  **Hex Insertion:** The hex sequence `ff:fe` is inserted in the middle to expand the MAC to 64 bits: `00:11:32:ff:fe:3e:8e:02`.
3.  **Universal/Local Bit Inversion:** The 7th bit of the first byte (the Universal/Local bit) is inverted:
    *   Byte `00` (binary `00000000`) becomes `02` (binary `00000010`).
4.  **IPv6 Address Assembly:** The calculated suffix `211:32ff:fe3e:8e02` is appended to the link-local prefix:
    *   *Resolved IPv6:* `fe80::211:32ff:fe3e:8e02`

If you are using a token with a hex suffix (e.g., `eno1|>...8e02`), Vane scans its active neighbor tables for a host matching that specific EUI-64 suffix and resolves it instantly.
