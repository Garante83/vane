# Vane CLI Quickstart & Reference Guide

Welcome to the **vane** quickstart guide! This document is designed to get you up and running with Vane in under two minutes, explaining the essential workflows and providing direct paths to advanced configuration handbooks.

---

## ⚡ The 2-Minute Master Workflow

If you are launching Vane for the first time, follow this step-by-step pipeline to master its core features:

### Step 1: Display the Interface Matrix
Run `vane` without arguments to see your active network adapters, index mapping, and copy-pasteable Unified IP Notation (UIP) templates:
```bash
vane
```

### Step 2: Test Loopback Resolution
Run a simple pre-flight ping using Vane notation to verify that the token translation engine works on your local loopback adapter:
```bash
vane ping "lo|:...1"
```

### Step 3: Discover Active Subnet Services
Let Vane scan and discover active network hosts and profile their running services:
```bash
vane discover --sweep
```
*(This performs an active, concurrent port and payload signature sweep, creating a high-performance profile of your neighborhood services).*

### Step 4: Map your First Semantic Token
Open the interactive TUI Cache Editor on your active interface (e.g., `eno1` or `eth0`) to register short semantic aliases (like `pve` or `nas`):
```bash
vane discover -e
```
*   Press **`A`** to add a new service entry.
*   Input a 3-character or 5-character token (e.g. `pve`).
*   Provide a name description, target IP address, and optional ports.
*   Save the entry.
*   Now, you can seamlessly connect to it using:
    ```bash
    vane ping "eno1|>...pve"
    vane ssh root@"eno1|>...pve"
    ```

---

## 📚 Specialized Handbooks Directory

For deep dives into advanced network engineering features, consult our specialized handbooks:

*   **1. Quickstart Guide:** Read [docs/01_quickstart.md](01_quickstart.md) for first-time setup and terminal walkthroughs.
*   **2. Unified IP Notation (UIP):** Read [docs/02_uip.md](02_uip.md) to understand basic prefix-matching, octet overrides, and dynamic DNS mappings.
*   **3. Resolution Explain Engine:** Read [docs/03_explain.md](03_explain.md) to see how Vane resolves notation step-by-step.
*   **4. Subnetwork Service Discovery (VSSD):** Read [docs/04_discovery.md](04_discovery.md) for custom signatures, active payload sweeps, and discovery configurations.
*   **5. Persistent Service Registry:** Read [docs/05_registry.md](05_registry.md) to understand local cache schemas, root ownership-restore, and self-healing backup routines.
*   **6. Advanced VSSD Manual:** Read [docs/06_vssd_advanced.md](06_vssd_advanced.md) to master stealth vs active sweeping, SSH/DNS fingerprinting banners, P2P registry mirroring, Hackordnung precedence rules, and JSON doctor heuristics.
*   **7. TCP Stealth Scanner:** Read [docs/07_scan.md](07_scan.md) for concurrent LAN host discovery and Vane token mapping.
*   **8. Sparkline Route Profiler:** Read [docs/08_trace.md](08_trace.md) for MTR-style path trace monitoring.
*   **9. Zero-Dependency Traffic Sniffer:** Read [docs/09_sniff.md](09_sniff.md) for native Linux raw socket HTTP/DNS capture.
*   **10. Secure TLS 1.3 P2P Transfer:** Read [docs/10_transfer.md](10_transfer.md) for encrypted ECDHE secure peer-to-peer file transfer.
*   **11. Advanced UIP Notation:** Read [docs/11_uip_advanced.md](11_uip_advanced.md) to master dynamic IPv6 Link-Local EUI-64 zones and float protection.
