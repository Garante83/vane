# Secure Peer-to-Peer (P2P) File Transfer

Vane includes a high-performance, cryptographically secured file transfer protocol (`vane send` and `vane recv`). This module is built for network administrators and users who need to transfer sensitive files (like configuration backups, database dumps, or diagnostic logs) directly between two hosts without relying on external cloud storage, third-party servers, or insecure plain-text tools like netcat.

---

## 1. Zero-Trust Handshake & Pairing Codes

To prevent unauthorized connection attempts on local networks, Vane uses a **Zero-Trust Pairing Handshake**:

1.  **Code Generation:** 
    When the sender initiates a transfer, Vane generates a random, cryptographically secure 6-digit numeric pairing code (e.g., `482910`).
2.  **HMAC Signature Key:**
    This pairing code acts as a shared secret between the sender and receiver. It is never transmitted in plain text across the network.
3.  **Connection Gatekeeping:**
    The receiver must input the exact pairing code. Vane uses this code as a key to calculate and verify an HMAC-SHA256 signature of the connection handshake. If the signature does not match, the connection is instantly dropped.

---

## 2. Cryptographic Security & TLS 1.3

Vane ensures absolute confidentiality and protection against eavesdropping using state-of-the-art cryptographic standards:

### Ephemeral Certificates (Zero-Trace Cryptography)
Instead of requiring pre-configured SSH keys or purchasing expensive SSL certificates, Vane generates flüchtige (**ephemeral**) TLS certificates completely in-memory at runtime:
*   **On-Demand CA:** Every time you start `vane send`, a new self-signed X.509 certificate with a strong 2048-bit RSA key is generated.
*   **No File Footprint:** These keys and certificates exist solely in the computer's volatile memory (RAM). They are never written to the disk and are completely destroyed when the transfer finishes.
*   **Forward Secrecy:** Because a new keypair is generated for every single transfer, even if an adversary captures the encrypted traffic and somehow compromises a machine later, past transfers remain completely unreadable.

### Forced TLS 1.3
Vane enforces **TLS 1.3** as the absolute minimum protocol version, eliminating legacy, vulnerable cipher suites (like RC4, 3DES, or MD5) and guaranteeing modern Authenticated Encryption with Associated Data (AEAD) algorithms (such as AES-GCM or ChaCha20-Poly1285).

---

## 3. How to Execute a Transfer

The transfer process is designed to be extremely straightforward and highly responsive.

### Step 1: Start the Sender
On the machine containing the file, run the send command:
```bash
vane send my_backup.tar.gz
```
Vane will open a secure listener and print the active transfer details:
```
[vane] ephemtal certificates generated in-memory.
[vane] Listening on 192.168.178.45:9090
[vane] Sharing secret pairing code: 582910
```

### Step 2: Receive the File
On the receiving machine, call the receive command, passing the sender's Vane IP/notation and the pairing code:
```bash
vane recv eno1|>...45 582910
```
Vane will instantly perform the cryptographic handshake, verify the shared secret, and stream the file directly over your local gigabit link with a high-fidelity progress bar.
