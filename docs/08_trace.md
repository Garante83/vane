# Live Path-Tracing & Latency Monitoring

> [!NOTE]
> **Availability:** Introduced in Vane **v1.0.2 (LTS)** | Companion Utility

Vane includes a real-time, interactive latency path tracer (`vane trace [target]`). This module functions similarly to the classic `mtr` (My Traceroute) utility, combining path traceroute discovery with continuous, multi-threaded latency probes. 

It provides network administrators and engineers with a highly visual, real-time diagnostic dashboard to pinpoint exactly which intermediate gateway or routing hop is introducing packet loss or latency spikes.

## 📋 Table of Contents
* [1. Path Hop Discovery & Fallbacks](#1-path-hop-discovery--fallbacks)
* [2. Multi-Threaded Real-Time Latency Probing](#2-multi-threaded-real-time-latency-probing)
* [3. High-Fidelity Terminal Sparklines](#3-high-fidelity-terminal-sparklines)
* [4. Visual Dashboard & Execution](#4-visual-dashboard--execution)

---

## 1. Path Hop Discovery & Fallbacks

When you launch a path trace, Vane first resolves the target address and maps out the intermediate routing hops (gateways) to the target:

1.  **Hop Pre-population:** Vane issues a low-timeout, progressive TTL sweep (using native system utilities like `traceroute`/`tracert` or `tracepath` for speed).
2.  **Greedy IP Filtering:** It parses routing table outputs, filters out loopbacks, and maps up to 15 intermediate hop IP addresses.
3.  **Adaptive Routing Fallback:** If your operating system lacks native path traceroute binaries, Vane falls back gracefully to monitoring your destination target directly, ensuring the utility never crashes or fails to execute.

---

## 2. Multi-Threaded Real-Time Latency Probing

Once the intermediate path is mapped, Vane launches continuous, parallelized network probes:

*   **Concurrent Pinging:** Vane spawns concurrent, lightweight goroutines to ping every single intermediate hop address simultaneously once per second.
*   **Non-Privileged Pings:** To remain completely accessible and safe, Vane uses the operating system's native non-privileged ICMP ping APIs, meaning you do **not** need root or sudo privileges to run a trace.
*   **Statistical Calculation:** For every hop, Vane tracks:
    *   **Loss%:** Percentage of sent probes that failed to receive a response.
    *   **Last:** Round-trip time (RTT) of the most recent probe.
    *   **Avg:** The mathematical average RTT of all successful probes.
    *   **Best / Worst:** The minimum and maximum RTT records.

---

## 3. High-Fidelity Terminal Sparklines

Vane features a highly aesthetic, real-time graphical sparkline history chart for every hop, drawn directly in your TUI terminal using UTF-8 vertical bar block characters:

```
▂ ▃ ▄ ▅ ▆ ▇ █
```

### Dynamic Latency Scaling
*   **Auto-Scaling:** Sparklines dynamically scale their vertical height relative to the minimum and maximum RTT recorded *specifically* for that hop. A small latency spike is instantly visible as a higher bar (`█`), while stable connections render as flat lower bars (` `).
*   **Loss Indicators:** If a packet is lost during a probe, Vane prints a red **`✖`** directly inside the sparkline history string.
*   **Firewall Warnings:** If an intermediate hop is protected by a firewall that blocks ICMP traffic completely, Vane prints a red `* no ICMP` warning in the sparkline column.

---

## 4. Visual Dashboard & Execution

Start a real-time path trace by passing a target IP address, a domain name, or a resolved Vane notation:
```bash
vane trace google.com
```

Vane will open the interactive path-tracing dashboard, updating all statistics and RTT sparklines in-place every second:

```
┌────────────────────────────────────────────────────────────────────┐
│  vane trace ─ Target: google.com (142.250.185.78)                  │
└────────────────────────────────────────────────────────────────────┘
  HOP IP ADDRESS      LOSS%  LAST    AVG     BEST    WRST    JITTER
 ────────────────────────────────────────────────────────────────────
  1   192.168.178.1   0.0%   1.2ms   1.4ms   1.1ms   2.5ms   ▂▃ ▂ ▂  
  2   10.0.0.1        0.0%   8.4ms   8.9ms   8.2ms   12.1ms  ▂█▃▂  ▂ 
  3   * (No Response) 100%   ──      ──      ──      ──      * no ICMP
  4   142.250.185.78  0.0%   14.2ms  15.1ms  14.0ms  22.4ms  ▂▃█▃ ▂▃ 
 ────────────────────────────────────────────────────────────────────
  [Ctrl+C] to exit. Monitoring latency in real-time...
```
*(Press `Ctrl+C` to terminate the traceroute loop cleanly.)*
