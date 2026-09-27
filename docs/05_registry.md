# VSSD Service Registry & Unified Service Notation (iface|>...[service])

> [!NOTE]
> **Availability:** Introduced in Vane **v1.1.0 (Production / Current Feature Branch)** | VSSD Suite

The VSSD (Vane Semi-Static Discovery) Cache is not just a static display table—it is the **dynamic service registry and local DNS engine** of Vane. By connecting passive neighbor discovery, manual administrative entries, and system command integration, Vane allows you to reference complex infrastructure using ultra-short service aliases embedded in a unified, consistent notation.

## 📋 Table of Contents
* [1. The Core Concept: A Local Service Directory](#1-the-core-concept-a-local-service-directory)
* [2. The Power of Unified Service Notation](#2-the-power-of-unified-service-notation)
* [3. Tool-Wide Integration (Synergy Examples)](#3-tool-wide-integration-synergy-examples)
* [4. The Interactive TUI Cache Editor (`vane discover -e`)](#4-the-interactive-tui-cache-editor-vane-discover--e)
* [5. Security & Cache Storage Internals](#5-security--cache-storage-internals)
* [6. Distributed P2P Registry Mirroring](#6-distributed-p2p-registry-mirroring)

---

## 1. The Core Concept: A Local Service Directory

In homelabs and corporate networks, remembering IP addresses (like `192.168.178.140` or `fe80::211:32ff:fe3e:8e02`) is cumbersome. Dynamic DNS (DDNS) often fails in dual-stack IPv6 networks or requires complex setup.

Vane solves this by maintaining a highly secure, local **Service Registry Cache** at:
```
~/.config/vane/cache.json
```

### Automatic & Manual Registry
This registry is populated in two ways:
1. **Persistent Verification (`vane discover -w -p`):** Registers verified local services (like Proxmox `pve` or Home Assistant `hass`) in the cache during an active neighborhood sweep. The `-p` or `--persistent` flag must be explicitly passed to persist the found services to disk.
2. **Interactive Editor (`vane discover -e`):** Allows administrators to manually register, edit, or delete custom service profiles.

---

## 2. The Power of Unified Service Notation

Once a service is registered in the VSSD cache under a specific 3-character token (e.g. `pve`), Vane activates **Unified Service Notation Resolution**.

To enforce a single consistent schema across all team members and eliminate different individual notations, loose standalone tokens (like `...pve`) are strictly forbidden and will be rejected. You must always use the unified notation prefixed with the interface index or name:
```
[interface] [direction] ...[token]
```
For example:
```
1|>...pve
# or
eno1|>...pve
```

### How Vane Resolves Unified Service Notation
When you pass `1|>...pve` to any Vane command, the UIP engine executes the following resolution chain:
1. **Token Extraction:** Detects the Vane notation structure, maps the interface prefix (`1` or `eno1`) to the real system interface, and extracts the service token (`pve`).
2. **Registry Query:** Queries `~/.config/vane/cache.json` for that specific interface and token.
3. **Instant Resolution:** Extracts the cached IP address and seamlessly binds the connection to it.

---

## 3. Tool-Wide Integration (Synergy Examples)

The unified service notation is fully integrated across all Vane subcommands, making it the ultimate multiplier for administrative productivity:

### Latency Tracing
Monitor the routing path and real-time latency of your Proxmox server without looking up its IP:
```bash
vane trace 1|>...pve
```

### Secure P2P File Transfer
Send a backup archive directly to your Home Assistant server:
```bash
vane send backup.tar.gz 1|>...hass
```

---

## 4. The Interactive TUI Cache Editor (`vane discover -e`)

Administrators can manage the local service directory using a pristine, terminal-based TUI Cache Editor:

```bash
vane discover -e
```

### Editor Commands & Rules
*   **`A` (Add Entry):** Registers a new custom service mapping.
*   **`E` (Edit Entry):** Updates an existing mapping.
*   **`D` (Delete Entry):** Removes a mapping cleanly from the cache.
*   **`C` (Clear Cache):** Wipes all cached entries for the selected network interface.
*   **`S` (Raw Edit):** Opens the raw JSON cache file in the terminal's system editor (defaulting to `nano` or `$EDITOR`).
*   **`R` (Rescue Backup):** Visible only when a corrupted cache file backup is found. Spawns the **Recovery Assistant** menu to rescue your settings.
*   **`Q` (Quit):** Quits the interactive editor.

### Architectural Safeguards & Visual Symmetries
To ensure database integrity and a clean terminal layout, the editor enforces strict safeguards:
1. **Strict 3-Character Tokens:** Service tokens must be exactly three lowercase alphabetical characters (a-z, e.g. `pot` for Portainer, `nas` for TrueNAS). This keeps the visual CLI discovery matrix perfectly aligned.
2. **Separation of Token & Name:** Vane keeps your technical 3-letter token separate from a descriptive spelled-out name/description (e.g., Token: `pot`, Name: `Portainer Server`). 
3. **Duplicate Prevention:** When editing or adding a token, Vane automatically deletes the old record if you change the token key, ensuring no orphan duplicate entries remain in the JSON registry.
4. **Symmetrical Index Alignment:** The index numbers (`[1]` to `[999]`) are formatted using left-aligned fixed-width padding (`%-5s`). This guarantees that your green arrows `➔` and server information fields remain perfectly aligned in vertical columns even when your registry grows to double or triple digits.

---

## 5. Security & Cache Storage Internals

Since the VSSD cache stores sensitive local infrastructure IPs, MAC addresses, and network interface names, Vane enforces **POSIX Owner-Only Security**:

*   **File Permissions (0600):** 
    The cache file `cache.json` is created with strict owner read/write permissions (`-rw-------`). Any unauthorized read or write access from other local user accounts is blocked by the operating system kernel.
*   **Self-Healing Config Cache:**
    In the event of a disk error or dynamic JSON corruption, Vane prevents application crashes or network resolution failures through its built-in self-healing runtime:
    1.  **Passive Detection:** If the database becomes unparseable on startup or cache lookup, the runtime fangs the error gracefully without throwing exceptions.
    2.  **Rescue Backup:** The corrupted cache is immediately backed up to `cache.json.corrupted` so that your custom manual entries are never permanently lost.
    3.  **Clean Re-initialization:** Vane spawns a fresh, fully valid JSON database (`{}`) in 0ms and moves on.
    4.  **Stale Backup Auto-Cleanup:** Stale `.corrupted` files are automatically cleaned up and deleted by Vane after 30 days to avoid cluttering the home directory.
*   **Built-in Auto-Repair JSON Doctor:**
    If a corrupted backup exists, pressing **`[R]`** in `vane discover -e` launches the **Corrupted Cache Recovery Assistant**:
    *   **Auto-Repair:** Runs automated diagnostic filters to heal 95% of manual editing mistakes:
        *   *Brace/Bracket Counter:* Counts open vs close delimiters and automatically appends missing `}` or `]` characters at the end of the file.
        *   *Trailing Comma Trimmer:* Automatically strips illegal trailing commas before closing braces.
        *   *Consecutive Comma Collapser:* Automatically collapses multiple consecutive commas (e.g. `,,,` or `, , ,` ➔ `,`).
        *   *Adjacent Object Comma Injector:* Injects missing commas between adjacent records.
    *   **System Editor Rescue:** Opens the corrupted backup directly in your terminal text editor. Once closed, Vane immediately validates your edits in real-time, offering to restore the repaired backup as your active cache.
*   **Clean Wiping:**
    You can wipe your service registry at any time using:
    ```bash
    vane discover -c
    ```
    This completely deletes the cache file, leaving no trace behind.

---

## 6. Distributed P2P Registry Mirroring

Vane allows you to export your curated registry maps from one master machine and import them securely onto other client devices in your local network using ephemeral TLS 1.3 tunnels. 

See the [Vane Service Discovery Manual](04_discovery.md#6-secure-registry-mirroring-export--import) for full usage instructions, command flags, and details on Vane's automated "Hackordnung" conflict resolution engine.

