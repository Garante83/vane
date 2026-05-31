# High-Performance Concurrent Subnet Scanning

> [!NOTE]
> **Availability:** Introduced in Vane **v1.0.2 (LTS)** | Companion Utility

Vane includes a built-in, ultra-fast, parallelized TCP subnet sweeper (`vane scan [interface]`). Designed as a zero-dependency diagnostic tool, it enables network administrators to quickly discover active hosts on a local network segment without needing external tools like `nmap` or `arp-scan`. 

It queries system configuration tables, computes active IP ranges, and performs non-privileged concurrent sweeps, outputting ready-to-copy dynamic Vane tokens for instant proxy routing.

---

## 1. Automated Network Segment Calculations

When you initiate a scan, Vane automatically calculates the active boundaries of your local segment:

1.  **Interface Inspection:** Vane queries the `netstate` module to extract the interface's current IPv4 configuration and subnet mask.
2.  **CIDR Range Resolution:** It computes the full host range of the active subnet block (e.g. `/24` or `/22` networks).
3.  **Boundary Protection:** It intelligently increments host addresses, automatically skipping the subnet identifier (network IP) and broadcast address to prevent network disruption.
4.  **Gateway MAC Resolution:** Extracts the default gateway IP from system routing tables and matches its MAC address from the kernel ARP cache.

---

## 2. Ultra-Fast Concurrent Verification

To achieve maximum scanning speed without high CPU overhead, the scanning engine utilizes Go's lightweight concurrency primitives:

*   **Worker Pool Architecture:** Vane spawns concurrent scanning workers that probe up to 254 subnetwork targets simultaneously.
*   **Low-Latency TCP Handshake:** It issues low-timeout, non-privileged TCP dial handshakes (200ms connection window) on a targeted list of common network service ports:
    *   *Standard:* `22` (SSH), `80` (HTTP), `443` (HTTPS)
    *   *Management:* `8006` (Proxmox), `8123` (Home Assistant), `32400` (Plex), `9000`/`9443` (Portainer/Paperless)
*   **The RST proof:** To guarantee high-fidelity detection, Vane intercepts `connection refused` (RST packet) responses. If a host explicitly rejects a connection on a port, Vane still registers the host as `ONLINE` because the device is alive and actively communicating!

---

## 3. High-Fidelity Vendor and Token Resolution

The results of the subnet sweep are beautifully compiled and enriched with system diagnostic data:

*   **Dynamic Notation Mapping:** Vane calculates the relative dot masking segment and prints the exact dynamic Vane token for every found host (e.g. `eno1|>...140` or `eno1|>...cf46` for MAC-matched targets). You can copy this notation directly and paste it into command wrappers!
*   **OUI Manufacturer Resolution:** The scanner inspects target MAC addresses against its built-in database of common hardware manufacturer prefixes:
    *   *Virtualization:* **Proxmox Server Solutions** (`bc:24:11`), VMware, VirtualBox, Microsoft Hyper-V, Parallels.
    *   *Embedded Systems:* Raspberry Pi, Ubiquiti, AVM Fritz!Box, Apple, Intel, Google, Huawei.

---

## 4. Visual Dashboard & Usage

Launch a subnet scan by specifying a physical network interface name:
```bash
vane scan eno1
```

Vane will display a live progress bar and print a gorgeous real-time dashboard inside your terminal:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  vane scan ─ Active Subnetwork Sweep (Interface: eno1 | Subnet: /24)          │
└──────────────────────────────────────────────────────────────────────────────┘
  Scanning subnet IPs... [██████████████████████████████████████] 100%

  IP ADDRESS       STATUS  OPEN PORTS       VANE NOTATION    MAC ADDRESS & VENDOR
 ──────────────────────────────────────────────────────────────────────────────
  192.168.178.1    ONLINE  [80,443]         eno1|>...1       00:1a:11:12:34:56 (Intel)
  192.168.178.50   ONLINE  [22]             eno1|>...50      52:54:00:12:34:56 (VirtualBox)
  192.168.178.140  ONLINE  [22,8006]        eno1|>...140     bc:24:11:a4:23:cc (Proxmox Server Solutions)
  192.168.178.201  ONLINE  [8123]           eno1|>...201     b8:27:eb:8f:90:12 (Raspberry Pi)
 ──────────────────────────────────────────────────────────────────────────────
  Discovered 4 active hosts in subnetwork range.
```

---

## 5. Security & Enterprise Tag (`nosweep`)

In professional and enterprise environments, scanning local subnets without authorization can violate strict corporate security policies and trigger intrusion detection warnings. 

To remain fully compliant with these environments, Vane features a modular build tag:

*   **Sweepsicherung (Enterprise Mode):** 
    By compiling Vane with the `nosweep` tag, you compile a sweepsafe binary that disables both active discovery sweeps (`discover -w`) and active subnet scanning (`vane scan`):
    ```bash
    make build-enterprise
    ```
*   When executing `vane scan` on an Enterprise-compiled binary, Vane terminates gracefully, outputting a safe corporate notice:
    ```
    [x] active neighborhood sweeping is disabled in this Enterprise build of Vane
    ```
