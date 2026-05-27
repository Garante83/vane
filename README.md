<p align="center">
  <img src="assets/vane_CLI_Logo.svg" alt="vane CLI Logo" width="350">
</p>

# Variable Arguments Network Executor (vane)

[![Go Report Card](https://goreportcard.com/badge/github.com/Garante83/vane)](https://goreportcard.com/report/github.com/Garante83/vane)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**vane** is a lightweight, zero-dependency command-line utility written in native Go that simplifies and automates network troubleshooting. It acts as an **intelligent, shell-safe proxy wrapper** around native networking tools (like `ping`, `ssh`, `curl`, `nmap`, `scp`, etc.) by dynamically resolving human-friendly interface-based syntax tokens into raw IPv4 or IPv6 addresses in real-time.

Rather than acting as a disjoint set of separate diagnostic tools, **vane** centers its built-in subcommands around the **Vane Notation**, allowing you to discover, profile, and interact with Vane tokens efficiently.

<p align="center">
  <img src="assets/vane-demo.gif" alt="vane SSH & Port-Mapping Demo" width="650">
</p>

---

## 1. Core Concept: The Vane Notation & Proxy Wrapper

At its heart, **vane** acts as a command proxy. You prefix any native command with `vane`, write your arguments using the high-visibility Vane syntax, and let the proxy do the work.

### Transparent Shell Handoff
Vane intercepts your command, parses and translates any Vane notation tokens into raw IP addresses, and hands execution directly back to the kernel.
```bash
vane ssh user@"eno1|>...33"
# Resolves in milliseconds and runs natively:
# ssh user@192.168.178.33
```

### Pre-Flight Port-Peeking
Before starting potentially hanging connections (like SSH or curl sessions to offline hosts), Vane performs an incredibly fast, non-blocking TCP connectivity check (200ms timeout) if a port is specified. If the target is unreachable, Vane halts execution immediately, saving you from long terminal hangs.

### Automatic SSH & SCP Port Flag Mapping
Vane is fully compatible with native protocol flag structures. If you supply an inline port inside a Vane token for `ssh` or `scp`, the proxy automatically strips the inline port to keep the IP clean and appends the proper command-line flag:
* `vane ssh user@"eno1|>...33:2222"` $\rightarrow$ executes `ssh user@192.168.178.33 -p 2222`
* `vane scp file.tar.gz user@"eno1|>...33:2222":/tmp/` $\rightarrow$ executes `scp file.tar.gz user@192.168.178.33 -P 2222:/tmp/`

### Interface Shorthands (Indices & Aliases)
Avoid typing long, case-sensitive physical adapter names (like `Ethernet 2` or `Wi-Fi`):
1. **Index-Based Matching**: Use numerical indices from the Vane matrix (e.g. `1|>...33`).
2. **Common Abbreviation Aliases**: Automatically maps standard Linux shorthand (e.g. `eth`, `wlan`, `wifi`) to their OS counterparts.
3. **Prefix Matching**: Case-insensitive partial matching (e.g. `ether` matches `Ethernet`).

---

## 2. Token Reference & Dynamic Resolution

Vane maps all network configurations directly to a standardized syntax:

| Modifier | Mode | Description | Example | Output Example |
|---|---|---|---|---|
| `>` | Outbound LAN | Overwrites suffix/octets of IPv4 | `eno1\|>...33` | `192.168.178.33` |
| `>` | Gateway | Resolves dynamic default gateway | `eno1\|>...gw` | `192.168.178.1` |
| `<` | External WAN | Resolves global IPv6 address | `eno1\|<...3e8e` | `2001:9731:...:3e8e` |
| `:` | Loopback | Standard local loopback | `lo\|:...1` | `::1` or `127.0.0.1` |
| `!` | APIPA Warning | Alerts and handles DHCP fallbacks | `eno1\|!...34` | `169.254.12.34` |

### Multi-Octet Suffix Overrides
The number of **dots** in the token specifies exactly how many octets of your local active IP are kept from the left:
* **3 Dots (`...`)** $\rightarrow$ Keeps **3 octets**, replaces the 4th: `eno1|>...33` $\rightarrow$ `192.168.178.33`
* **2 Dots (`..`)** $\rightarrow$ Keeps **2 octets**, replaces the 3rd & 4th: `eno1|>..100.33` $\rightarrow$ `192.168.100.33`
* **1 Dot (`.`)** $\rightarrow$ Keeps **1 octet**, replaces the 2nd, 3rd & 4th: `eno1|>.2.100.33` $\rightarrow$ `192.2.100.33`

### MAC Suffix to IPv4 Resolution
If you only know the EUI-64 MAC suffix of a machine but want to connect using IPv4, pass it under the LAN modifier (`>`). Vane matches it against the adapter's hardware MAC and resolves it directly to your active local IPv4:
* `eno1|>...3e8e` $\rightarrow$ matches `eno1` and resolves to `192.168.178.53`

### Intelligent Range-Peeking (`> 255` Safeguard)
If a purely numeric host part exceeds `255` (e.g. `300` or `1024`), Vane automatically classifies it as a hexadecimal MAC/IPv6 suffix rather than trying to construct an invalid IPv4 segment.

### Interactive Infocenter & Dynamic Conversion (`vane -c`)
Query and cross-reference network configurations bidirectionally on any active adapter:
* **Quick-map EUI-64 to decimal IPv4**:
  `vane -c eno1 1ac0:4dff:feda:3e8e` $\rightarrow$ Output: `-> IPv4 Equivalent: 192.168.178.53`
* **Dynamic Subnet-to-Syntax Translation**:
  Passing multi-octet values (like `100.33`) dynamically calculates the correct Vane syntax suggestion:
  `vane -c eno1 100.33` $\rightarrow$ Output:
  ```text
  -> Vane-Syntax:   eno1|>..100.33   (Automatically resolved to 2-dot syntax!)
  -> IPv4-Standard: 192.168.100.33
  ```

---

## 3. Integrated Companion Utilities

While these built-in diagnostics are designed to seamlessly support the Vane Notation, they can also be used completely independently as standalone, simple network utilities in their own right—even if industry-standard tools already exist.

### A. Subnet Scanner (`vane scan [interface]`)
An ultra-fast, concurrent TCP stealth sweeper. It discovers active hosts on your subnet, sweeps common ports, queries the kernel ARP table, and outputs **direct copy-pasteable Vane tokens** in a stramm aligned grid.
* *Purpose:* Instantly discover Vane-Notation targets currently online in your LAN.

### B. Interactive Route & Latency Profiler (`vane trace <target>`)
A beautiful, real-time MTR-style path and jitter profiler. It queries routing hops and concurrent-pings them to produce live ASCII sparkline graphs.
* *Purpose:* Fully supports Vane-Syntax (e.g., `vane trace "eno1|>...gw"`).

### C. Traffic Sniffer (`vane sniff [interface]`)
Pure-Go zero-dependency traffic capture tool. Monitors HTTP requests and DNS queries in real-time using native Linux Raw Sockets (`AF_PACKET`) or falls back to a PowerShell connection-to-process mapper on Windows.
* *Purpose:* Debug protocol flows coming from resolved Vane targets.

### D. Secure P2P Streaming (`vane send` / `vane recv`)
Zero-config, peer-to-peer encrypted file transfers using ephemeral TLS 1.3 + ECDHE, session-bound HMAC pairing codes, and parallel SHA-256 integrity verification.
* *Purpose:* High-speed file sharing between resolved Vane targets.

---

## 4. Visual Concept

When you run `vane` without arguments, it generates a perfect, vertically-aligned reporting grid:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│  vane ─ Local Network Interface Matrix                                       │
└──────────────────────────────────────────────────────────────────────────────┘
  INTERFACE   STATUS    TYPE       VANE-SYNTAX        REAL IP / DESIGNATION     
 ──────────────────────────────────────────────────────────────────────────────
  lo          [ UP ]    Loopback   lo   |:...1        127.0.0.1 / ::1
  eno1        [ UP ]    LAN (v4)   eno1 |>...53       192.168.178.53
                        (Gateway)  eno1 |>...gw       192.168.178.1
                        WAN (v6)   eno1 |<...3e8e     2001:9731:b7c6:...:3e8e
 ──────────────────────────────────────────────────────────────────────────────
```

---

## 5. Quick Start Examples

### 1. Dynamic Ping to Default Gateway
```bash
vane ping -c 3 "eno1|>...gw"
```

### 2. Fast SSH to an IPv6 Device (with Auto-Port Flag Mapping)
```bash
vane ssh user@"eno1|<...3e8e:2222"
```

### 3. Port-Peeking with curl
```bash
vane curl "http://[eno1|<...3e8e]:8080/"
```

### 4. Interactive Infocenter (Conversion Mode)
```bash
vane -c eno1 100.33
```

### 5. High-Visibility Subnet Scan (Discovering Vane Tokens)
```bash
vane scan eno1
```

---

## Platform Support Status

* **Linux**: 🐧 **Fully Supported**. Tested across multiple environments (LXC, physical hosts).
* **macOS (Darwin)**: 🍎 **Experimental / Untested**. While compiled via cross-compilation target and structurally compatible, macOS raw sockets and interface naming have not been heavily verified in live settings.
* **Windows**: 🪟 **Alpha / Restricted Support**. Works as a basic concept, but currently features known platform limitations (e.g., sniffing falls back to dynamic TCP process mapping via PowerShell). Expect rough edges as active testing on Windows has been limited.

---

## 6. Installation

### From Source
```bash
# Clone the repository
git clone https://github.com/Garante83/vane.git
cd vane

# Compile and install globally (requires sudo to copy to /usr/local/bin)
make install
```

### Uninstallation
```bash
make uninstall
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
