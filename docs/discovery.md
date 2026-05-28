# Vane Service Discovery & Verification

Vane is designed from the ground up as a defensive, network-safe administration tool. Unlike standard diagnostic utilities that perform aggressive, high-noise subnet sweeps (which frequently trigger Intrusion Detection Systems and cause network congestion), Vane implements a strictly controlled **passive-first, targeted-verification** architecture.

> [!NOTE]
> The active verification scanner (`-s` / `--scan`) is currently part of Vane's active feature branch (`feat/vssd-service-discovery`) and is slated for the upcoming pre-release.

---

## 1. Default Mode: Passive Service Resolution

When you run a standard discovery command:
```bash
vane discover
```
Vane operates in **100% Passive Mode**. In this state, the utility sends **zero network packets** out of your interface. Instead, it reconstructs your local network state by inspecting data the host operating system already has:

1. **System Neighbor Tables (ARP & NDP):**
   Vane inspects the kernel's neighbor table (reading `/proc/net/arp` on Linux or system neighbor states on other OSes) to discover hosts that have already established communication with your local machine.
2. **Local DNS Cache:**
   Vane performs fast, standard OS-level local lookups for `.local` mDNS domains.
3. **Passive Multicast Listener:**
   Vane listens for passive multicast advertisements (like mDNS or SSDP) that devices naturally broadcast into the network (e.g. Synology NAS, Home Assistant dashboards).

This approach ensures zero overhead, making Vane completely invisible to any network monitoring systems while gathering immediate local intelligence.

---

## 2. Active Verification: Targeted Known-Host Peeking

If you require real-time verification of active services, you can trigger targeted peeking using the scan flag:
```bash
vane discover -s
```
or
```bash
vane discover --scan
```

### How Vane Safe Scanning Differs from Aggressive Port Scanners
A standard port scanner typically loops through an entire subnet CIDR block (e.g., trying to connect to port 80 on `192.168.1.1` all the way to `192.168.1.254`). This behavior is highly disruptive and instantly flagged by corporate firewalls.

Vane protects your network integrity by using **Targeted Verification**:
1. **Target Compilation:**
   Instead of scanning a range, Vane compiles a strict target list containing only:
   * IPs that are already present as active in the operating system's local ARP/NDP table.
   * IPs of custom services you have manually registered using the built-in interactive cache editor (`vane discover -e`).
2. **Surgical Verification:**
   Vane attempts TCP connects *only* on the ports defined by known service signatures for those specific target IPs.
3. **Payload Peeking:**
   If a port responds, Vane performs a lightweight, secure handshake to grab HTTP titles or protocol banners (e.g., checking for the Redis `+PONG` or Elasticsearch `"you know, for search"` response).
4. **No Range Sweeping:**
   There is no range-iteration logic in the codebase. If an IP does not already exist in your neighbor cache or manual configuration, Vane will never send a packet to it.

---

## 3. Supported Service Signatures

Vane identifies services using a high-precision signature matrix, categorized into homelab and enterprise infrastructure categories:

| Token | Service Name | Default Ports | Verification Method |
| :--- | :--- | :--- | :--- |
| **`pve`** | Proxmox VE | `8006` | HTTP title peeking |
| **`nas`** | Network Attached Storage | `5000, 5001, 445, 80, 443` | OUI MAC prefix matching & HTTP peeking |
| **`pi`** | Raspberry Pi | `22` | OUI matching & mDNS confirmation |
| **`hass`** | Home Assistant | `8123` | HTTP dashboard payload confirmation |
| **`pgs`** | PostgreSQL Database | `5432` | Targeted TCP verification |
| **`mys`** | MySQL / MariaDB | `3306` | Targeted TCP verification |
| **`rds`** | Redis Key-Value Store | `6379` | Custom TCP `PING` payload matching |
| **`mgo`** | MongoDB | `27017` | Targeted TCP verification |
| **`els`** | Elasticsearch | `9200` | HTTP banner query (`you know, for search`) |
| **`k8s`** | Kubernetes API Server | `6443` | HTTP API response verification |
| **`dck`** | Docker Daemon API | `2375, 2376` | API response string peeking |
