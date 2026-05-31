# Live Network Sniffing & Packet Decoding

> [!NOTE]
> **Availability:** Introduced in Vane **v1.0.2 (LTS)** | Companion Utility

Vane includes a low-level, high-fidelity live packet sniffer (`vane sniff [interface]`). This module is built for network administrators who need real-time visibility into active protocols, domain lookups, and unencrypted web requests traversing an interface, without having to spawn heavy, complex tools like Wireshark or tcpdump.

## 📋 Table of Contents
* [1. Raw Socket Architecture & Privilege Gates](#1-raw-socket-architecture--privilege-gates)
* [2. On-the-Fly Protocol Decoding](#2-on-the-fly-protocol-decoding)
* [3. Operating the Sniffer](#3-operating-the-sniffer)

---

## 1. Raw Socket Architecture & Privilege Gates

To capture packets directly from the network interface card (NIC) without third-party libraries (like libpcap), Vane taps directly into the operating system's kernel raw socket API:

*   **Linux Raw Sockets:** Vane instantiates a raw packet socket using `syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)`.
*   **Root Privilege Requirement:** Because raw socket captures bypass the OS protocol stack and capture all incoming and outgoing frames on the physical layer, this capability is restricted by the OS kernel. Vane requires root privileges to initialize this socket. 
    *   *Execution command:* `sudo vane sniff eno1`
*   **Kernel Interface Binding:** Once initialized, the raw socket is bound strictly to the specified physical interface (via `syscall.SockaddrLinklayer` and `syscall.Bind`), ensuring Vane only captures frames traversing your target interface, preventing CPU overhead from irrelevant traffic.

---

## 2. On-the-Fly Protocol Decoding

Vane processes raw ethernet frames in real-time, executing a highly efficient decoding pipeline that decodes packets layer by layer:

```
[Physical Frame] ➔ [Ethernet Decoder] ➔ [IPv4 Layer] ➔ [Protocol Demuxer]
                                                               ├─➔ [ICMP Decoder]
                                                               ├─➔ [UDP / DNS Decoder]
                                                               └─➔ [TCP / HTTP Decoder]
```

### A. ICMP Decoder (Network Diagnostics)
Vane decodes standard ICMP packets (Protocol `1`), identifying system pings and path-trace packets:
*   **Ping Echo Requests (Type 8):** Logged as `PING REQUEST`.
*   **Ping Echo Replies (Type 0):** Logged as `PING REPLY`.
*   **Time Exceeded (Type 11):** Transmitted by intermediate routers when a packet's Time-To-Live (TTL) reaches zero.
*   **Destination Unreachable (Type 3):** Indicates routing failures.

### B. UDP DNS Decoder (Domain Query Parsing)
For UDP packets (Protocol `17`) traversing port `53`, Vane parses raw DNS question sections to extract queried domains:
*   **Binary Query Decoding:** Vane extracts domain labels from standard DNS questions (demarcating lengths and combining labels with dot separators).
*   **Performance Safety:** DNS pointer compression labels (which require complex state tracking) are bypassed for lightweight, real-time logging performance.

### C. TCP HTTP Decoder (Web Request Sniffing)
For TCP streams (Protocol `6`) traveling over standard web ports (`80`, `8080`, `8000`), Vane parses the raw payload to sniff unencrypted HTTP requests:
*   **Method Detection:** Inspects the request line for HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`).
*   **Header Extraction:** Automatically parses the stream to extract the `Host:` header to display exactly which server is being targeted.
*   **Aligned Column Output:** Pads methods (e.g., `GET:`, `POST:`) to uniform widths to maintain pristine column layouts.

---

## 3. Operating the Sniffer

To monitor active traffic, pass your target interface name to the sniff command:
```bash
sudo vane sniff eno1
```
Vane will open a high-visibility terminal dashboard and log traffic as it traverses the network card in real-time:

```
┌────────────────────────────────────────────────────────────────────────┐
│  vane sniff ─ Monitoring HTTP & DNS Traffic on eno1                  │
└────────────────────────────────────────────────────────────────────────┘
  TIME      PROTO  SOURCE           TARGET           DETAIL
 ────────────────────────────────────────────────────────────────────────
  11:42:05  DNS    192.168.178.45   1.1.1.1          QUERY: google.com
  11:42:06  ICMP   192.168.178.45   142.250.185.78   PING REQUEST
  11:42:06  ICMP   142.250.185.78   192.168.178.45   PING REPLY
  11:42:08  HTTP   192.168.178.45   192.168.178.10   GET: /index.html (Host: pi.local)
```
*(Press `Ctrl+C` to terminate the packet sniffing loop cleanly.)*
