# Secure Peer-to-Peer (P2P) File Transfer

> [!NOTE]
> **Availability:** Introduced in Vane **v1.0.2 (LTS)** | Companion Utility

Vane includes a high-performance, cryptographically secured file transfer protocol (`vane send` and `vane recv`). This module is built for network administrators and users who need to transfer sensitive files (like configuration backups, database dumps, or diagnostic logs) directly between two hosts without relying on external cloud storage, third-party servers, or insecure plain-text tools like netcat.

---

## 1. Zero-Trust Handshake & Pairing Codes

To prevent unauthorized connection attempts on local networks, Vane uses a **Zero-Trust Pairing Handshake**:

1.  **Code Generation:** 
    When the receiver is started (`vane recv`), Vane generates a random, cryptographically secure 8-digit grouping pairing code (e.g., `5829-10`).
2.  **HMAC Signature Key:**
    This pairing code acts as a shared secret between the sender and receiver. It is never transmitted in plain text across the network.
3.  **Connection Gatekeeping:**
    The sender must specify the pairing code. Vane uses this code as a key to calculate and verify an HMAC-SHA256 signature of the connection handshake over the TLS Exporter material. If the signature does not match, the connection is instantly dropped.

---

## 2. Cryptographic Security & TLS 1.3

Vane ensures absolute confidentiality and protection against eavesdropping using state-of-the-art cryptographic standards:

### Ephemeral Certificates (Zero-Trace Cryptography)
Instead of requiring pre-configured SSH keys or purchasing expensive SSL certificates, Vane generates flüchtige (**ephemeral**) TLS certificates completely in-memory on the receiver at runtime:
*   **On-Demand CA:** Every time you start `vane recv`, a new self-signed X.509 certificate with a strong ECDSA key (P-256) is generated.
*   **No File Footprint:** These keys and certificates exist solely in the computer's volatile memory (RAM). They are never written to the disk and are completely destroyed when the transfer finishes.
*   **Forward Secrecy:** Because a new keypair is generated for every single transfer, even if an adversary captures the encrypted traffic and compromises a machine later, past transfers remain completely unreadable.

### Forced TLS 1.3
Vane enforces **TLS 1.3** as the absolute minimum protocol version, eliminating legacy, vulnerable cipher suites (like RC4, 3DES, or MD5) and guaranteeing modern Authenticated Encryption with Associated Data (AEAD) algorithms (such as AES-GCM or ChaCha20-Poly1305).

---

## 3. How to Execute a Transfer

The transfer process is designed to be extremely straightforward and highly responsive.

### Step 1: Start the Receiver
On the destination machine that should receive the file, run the receive command:
```bash
vane recv
```
*(You can optionally specify a custom port using `--port <port>`, e.g., `vane recv --port 8484`.)*

Vane will generate the ephemeral certificate in-memory, open a secure listener, and display the active transfer details:
```text
┌────────────────────────────────────────────────────────────────────┐
│  vane recv ─ Standing by for incoming file transfer...             │
│  Listening on: [::]:8484 (All Interfaces)                         │
│  Receiver IPs: 192.168.178.53                                      │
│  Pairing Code: 192.168.178.53#5829-10                              │
│                                                                    │
│  Please run on sender:                                             │
│  vane send <file> --code 192.168.178.53#5829-10                     │
└────────────────────────────────────────────────────────────────────┘
```

### Step 2: Start the Sender
On the source machine containing the file, execute the send command. Pass the file path and the pairing code shown by the receiver (using either the raw IP or a resolved Vane Notation token):
```bash
vane send my_backup.tar.gz --code 192.168.178.53#5829-10
```
*Alternatively, using Vane Notation to target the receiver:*
```bash
vane send my_backup.tar.gz --code "eno1|>...53#5829-10"
```

Vane will instantly connect to the receiver, perform the cryptographic handshake, verify the shared secret, stream the file directly over your network link with a high-fidelity progress bar, and finally verify the SHA-256 integrity checksum.
