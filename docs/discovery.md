# Vane Service Discovery & Verification

Vane is designed from the ground up as a defensive, network-safe administration tool. Unlike standard diagnostic utilities that perform aggressive, high-noise subnet sweeps (which frequently trigger Intrusion Detection Systems and cause network congestion), Vane implements a strictly controlled **passive-first, targeted-verification** architecture.

> [!NOTE]
> This codebase represents the active feature branch introducing **VSSD (Vane Semi-Static Discovery)**, which implements local service registries, the interactive cache TUI editor, and targeted host verification.

---

## 1. Default Mode: Passive Service Resolution

When you run a standard discovery command:
```bash
vane discover
```
Vane operates in **100% Passive Mode**. In this state, the utility sends **zero network packets** out of your network interface. Instead, it reconstructs your local network state by inspecting data the host operating system already has, and compares it against Vane's static service signature matrix:

1. **System Neighbor Tables (ARP & NDP):**
   Vane inspects the kernel's neighbor table (reading `/proc/net/arp` on Linux or system neighbor states on other OSes) to discover active IP/MAC addresses that have already established communication with your local machine.
2. **Local DNS Cache & OS mDNS Resolving:**
   Vane performs standard OS-level local lookups for `.local` mDNS domains matching known signature patterns (such as `proxmox.local`, `synology.local`, `raspberrypi.local`, or the token names directly).
3. **Passive Signature Comparison:**
   Discovered local hosts are compared internally against static **Service Signatures** (such as MAC OUI hardware address prefixes like `00:11:32` for Synology/NAS, or `b8:27:eb` for Raspberry Pi) to recognize and map the hosts without ever initiating network connections.

This approach ensures zero overhead, making Vane completely invisible to any network monitoring systems while gathering immediate local intelligence.

> [!IMPORTANT]
> **Limitations of Purely Passive Resolution:**
> Because passive mode is 100% silent and sends zero network packets, it cannot scan ports or peek payloads. Consequently, software-based services running on general-purpose hardware (such as Proxmox VE, Open WebUI, Paperless-ngx, or Nextcloud) **will not be detected** in passive mode on a fresh installation *unless*:
> 1. They successfully announce themselves via mDNS and your host OS resolver caches them (e.g. resolving `proxmox.local`).
> 2. Or they are loaded from Vane's local cache (`cache.json`) after you have consciously run an active sweep (`vane discover -w -p`) with the persistent flag at least once to populate your environment.
>
> **Conscious Control & Workflow:**
> Vane respects your network integrity. Passive mode (`vane discover`) only reads what is already known to the OS or manually cached. Active sweeps (`-w`) and single scans (`-s`) must be **consciously started** by you, and their results are only saved to the disk if you explicitly request it using the persistent flag (`-p`).

---

## 2. Active Verification: Targeted Known-Host Peeking
---

If you require real-time verification and deeper diagnostic details for active services, you can trigger active peeking. Vane supports two active scanning behaviors:

### A. Subnetwork Neighbor Sweep
To actively sweep all known network hosts (derived from the local ARP cache neighbor tables), use the `--sweep` or `-w` flag:
```bash
vane discover -w
# or
vane discover --sweep
```

### B. Targeted Single-Host Scan
If you want to actively scan a **specific target** (e.g. to identify a service running on a custom port or to verify a single unmapped address), you can specify the target using the `--specific` or `-s` flag, or by simply passing the target IP/notation directly (which automatically triggers an active single-host scan):
```bash
# Using the specific flag
vane discover -s 192.168.178.140

# Or simply passing the target directly (automatically performs targeted verification)
vane discover "eno1|>...140"
vane discover "1|>...pve"
vane discover 192.168.178.140
```
> [!IMPORTANT]
> To enforce a single, consistent schema across teams, loose standalone tokens (like `...pve`) are strictly forbidden as scan targets and will be rejected. Always prefix the notation with the interface index or name.

This performs port verification and payload peeking strictly limited to that designated target, avoiding any sweeps.


### Automatic Cache Update & Existence Gate
To ensure defensive caching without unwanted disk clutter:
1. **Cache Existence check:** If your local service cache (`~/.config/vane/cache.json`) has already been initialized (either via a persistent scan `discover -p` or the interactive editor `discover -e`), Vane **automatically updates** your cache with any newly scanned and verified service entries.
2. **Defensive Isolation:** If no cache file exists on the system, Vane performs the active resolution in memory but does **not** create or write a new cache file to the disk, leaving your system completely pristine unless you explicitly request persistence using `--persistent` (`-p`).

### How Vane Safe Scanning Differs from Aggressive Port Scanners
A standard port scanner typically loops through an entire subnet CIDR block (e.g., trying to connect to port 80 on `192.168.1.1` all the way to `192.168.1.254`). This behavior is highly disruptive and instantly flagged by corporate firewalls.

Vane protects your network integrity by using **Targeted Active Verification**:
1. **Target Compilation:**
   Instead of scanning a range, Vane compiles a strict target list containing only:
   * The single target IP/token passed in (if running a targeted single-host scan).
   * IPs that are already present as active in the operating system's local ARP/NDP table (if running a full scan).
   * IPs of custom services you have manually registered using the built-in interactive cache editor (`vane discover -e`).
2. **Surgical Verification:**
   Vane attempts TCP connects *only* on the ports defined by known service signatures for those specific target IPs (e.g., port `8006` for Proxmox VE or port `8123` for Home Assistant).
3. **Payload Peeking:**
   If a port responds, Vane performs a lightweight, secure handshake to grab HTTP titles or protocol banners (e.g., checking for the Redis `+PONG` or Elasticsearch `"you know, for search"` response). This active probe gathers the critical data needed for precise, high-fidelity verification and mapping.
4. **Smart Neighborhood Sweep (No Blind Range Iteration):**
   Vane's active sweep (`--sweep` / `-w`) is a highly targeted process. Instead of blindly scanning the entire IP range of a subnet, it only sweeps the active devices already cached in your operating system's ARP table or manual registry. If an IP does not exist in your local neighbor cache, Vane will never send a probe to it, keeping the sweep completely silent and safe for corporate firewalls.

### Confidence-Based Matching (Anti-False-Positive Gate)
Vane does **not** blindly report a service just because a generic port (like 80 or 443) is open. The matching engine requires **strong evidence** before it reports a discovery:

| Evidence Level | Examples | Sufficient alone? |
| :--- | :--- | :--- |
| **Payload Fingerprint** | HTTP body contains `proxmox`, `grafana`, `portainer` etc. | ✅ Yes (highest confidence) |
| **MAC OUI Match** | Device MAC starts with `00:11:32` (Synology), `b8:27:eb` (Raspberry Pi) | ✅ Yes (hardware-level proof) |
| **Unique Port Open** | `8006` (PVE), `8123` (HASS), `32400` (Plex), `5432` (PostgreSQL) | ✅ Yes (port is service-specific) |
| **Ambiguous Port Open** | `80`, `443`, `22`, `53`, `445` | ❌ No (too generic, shared by many services) |

> [!IMPORTANT]
> If a host only has ambiguous ports like 80 or 443 open, Vane will **not** report it as any specific service unless additional evidence (OUI or payload) confirms its identity. This eliminates the false-positive problem of every web-enabled device being reported as 10+ different services simultaneously.

---

## 3. Supported Service Signatures

Vane identifies services using a high-precision signature matrix. Each entry shows the token, the human-readable display name, and the verification methods used:

### Homelab & Smart Home
| Token | Display Name | Default Ports | Verification Method |
| :--- | :--- | :--- | :--- |
| **`pve`** | Proxmox VE | `8006` | HTTP payload fingerprint |
| **`pbs`** | Proxmox Backup Server | `8007` | HTTP payload fingerprint |
| **`pmg`** | Proxmox Mail Gateway | `8006` | mDNS confirmation |
| **`nas`** | Network Attached Storage | `5000, 5001, 445, 80, 443` | OUI (Synology/QNAP) + HTTP fingerprint |
| **`pi`** | Raspberry Pi | `22` | OUI (Raspberry Pi Foundation) + mDNS |
| **`hass`** | Home Assistant | `8123` | HTTP payload fingerprint |
| **`rtr`** | Router / Gateway | `80, 443, 22` | OUI (AVM/TP-Link) + mDNS |
| **`unf`** | UniFi Controller | `8443, 8080` | OUI (Ubiquiti) + HTTP fingerprint |
| **`dns`** | DNS / Ad-Blocker | `53, 80, 443, 3000` | HTTP fingerprint (Pi-hole/AdGuard) |
| **`owu`** | Open WebUI | `8080, 3000` | HTTP payload fingerprint |
| **`ncd`** | Nextcloud | `80, 443, 8080` | HTTP payload fingerprint |
| **`ppl`** | Paperless-ngx | `8000, 8010` | HTTP payload fingerprint |
| **`plx`** | Plex Media Server | `32400` | HTTP payload fingerprint |
| **`jly`** | Jellyfin | `8096, 8920` | HTTP payload fingerprint |
| **`iot`** | IoT Device (ESP/Shelly) | `80, 1883` | OUI (Espressif) |
| **`kam`** | IP Camera / NVR | `80, 443, 554, 8000` | OUI (Hikvision/Axis/Dahua) |
| **`prt`** | Network Printer | `9100, 631, 80` | OUI (HP/Canon/Epson) |

### Enterprise & DevOps
| Token | Display Name | Default Ports | Verification Method |
| :--- | :--- | :--- | :--- |
| **`pgs`** | PostgreSQL | `5432` | Unique port TCP |
| **`mys`** | MySQL / MariaDB | `3306` | Unique port TCP |
| **`rds`** | Redis | `6379` | TCP `PING`→`+PONG` payload |
| **`mgo`** | MongoDB | `27017` | Unique port TCP |
| **`els`** | Elasticsearch | `9200` | HTTP `"you know, for search"` |
| **`k8s`** | Kubernetes API | `6443` | HTTP API response |
| **`dck`** | Docker Daemon | `2375, 2376` | HTTP API fingerprint |
| **`mon`** | Monitoring (Grafana) | `3000, 9090, 9100` | HTTP payload fingerprint |
| **`pot`** | Portainer | `9000, 9443` | HTTP payload fingerprint |
| **`git`** | Git Server | `22, 80, 443, 3000` | HTTP fingerprint (Gitea/GitLab) |
| **`mio`** | MinIO Object Storage | `9000, 9001` | HTTP payload fingerprint |
| **`val`** | HashiCorp Vault | `8200` | HTTP payload fingerprint |
| **`emx`** | MQTT Broker | `1883, 8883, 18083` | Unique port TCP |
| **`vpn`** | VPN Gateway | `1194, 51820` | Unique port TCP |
| **`vwr`** | VMware ESXi / vCenter | `443, 902` | Unique port (902) + mDNS |
| **`hvs`** | Hyper-V / Windows Server | `5985, 5986, 3389` | Unique port TCP |

---

## 4. Enterprise-Safe Compilation (Compiler Flag `nosweep`)

In strict corporate environments, active subnetwork sweeps of local IP neighborhoods are often considered unauthorized network scans and are flagged by security appliances (IDS/IPS). 

To ensure complete compliance with corporate network policies, Vane provides a dedicated **Enterprise-Safe Build** target.

### Standard Build (Home/Private)
Compiled via:
```bash
make build
# or
make install
```
Permits the use of active neighborhood sweeps (`vane discover --sweep`).

### Enterprise Build (Sweeps Disabled)
Compiled via:
```bash
make build-enterprise
# or
make install-enterprise
```
This sets the Go compiler tag `-tags nosweep`. In this build, any attempt to run `--sweep` or `-w` is intercepted and blocked with a policy notice. Passive discovery, manual editor entries, and single-host targeted lookups (`vane discover 192.168.178.140`) remain fully operational, ensuring a secure, compliant network tool.

---

## 5. Reverse Proxies & the Discovery Boundary

A common homelab and enterprise pattern is to place all internal services behind a **reverse proxy** (such as Nginx Proxy Manager, Traefik, or Caddy). This is excellent practice from a security and certificate management perspective — and it is also the reason why those backend services will not be auto-detected by Vane's active fingerprinting.

### Why fingerprinting fails behind a proxy

Vane's payload peeking works by connecting directly to a host's IP and port and inspecting the HTTP response body for service-specific keywords (e.g. `proxmox`, `nextcloud`, `gitea`). A reverse proxy correctly intercepts any request that arrives without the expected `Host` header and either returns a generic error page or redirects the client — intentionally hiding the backend identity.

```
# What Vane does during a sweep:
GET / HTTP/1.1
Host: 192.168.178.203   ← direct IP, no domain

# What Nextcloud expects:
GET / HTTP/1.1
Host: nextcloud.lan     ← reverse proxy routes this correctly
```

Because the proxy does exactly its job, the fingerprint receives no identifiable content and the service is not reported. **This is expected behavior, not a bug.**

> [!NOTE]
> Services with truly unique ports (e.g. Proxmox VE on `8006`, Portainer on `9443`, Jellyfin on `8096`) are still reliably detected because their ports are opened directly on the backend host — the proxy does not need to expose them separately for Vane to find them via TCP.

### Recommended workflow for proxied setups

For services that are exclusively accessible behind a reverse proxy, the correct approach is to populate the Vane cache **once** using the interactive editor, and then rely on silent cache resolution from that point on:

```bash
# Open the interactive cache editor
vane discover --edit
# or
vane discover -e
```

Inside the editor you can register the known IP-to-token mappings for your proxied services (e.g. `ncd → 192.168.178.203`). Once saved, `vane discover` will resolve them instantly from the local cache without any network traffic.

> [!IMPORTANT]
> The combination of **automatic detection** (for services with unique ports or OUI-identifiable hardware) and **manual cache entries** (for services behind a reverse proxy) gives you the best of both worlds: zero-footprint daily resolution with accurate, complete service maps even in hardened proxy environments.
