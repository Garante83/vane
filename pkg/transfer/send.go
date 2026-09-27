// Package transfer implements zero-config, peer-to-peer encrypted file
// transfers (vane send / recv). Sessions use ephemeral TLS 1.3 with ECDHE,
// session-bound HMAC pairing codes and parallel SHA-256 integrity checks.
// It also supports registry-based cache exchange between peers.
package transfer

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"vane/pkg/util"
)

// PerformSend streams a file securely to the receiver using ECDHE + HMAC authorization
func PerformSend(filePath, code string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	fi, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	fileSize := fi.Size()

	// Parse code to get receiver's address
	// Standard port is 8484. If the code is passed as `192.168.178.53:8484#7392-1845`, parse it.
	// We allow target address before code: e.g. `192.168.178.53#7392-1845` or simply `--code 7392-1845` (broadcast discover)
	targetAddr := "127.0.0.1:8484"
	cleanCode := code
	if idx := strings.Index(code, "#"); idx != -1 {
		addrPart := code[:idx]
		cleanCode = code[idx+1:]
		if !strings.Contains(addrPart, ":") {
			targetAddr = addrPart + ":8484"
		} else {
			targetAddr = addrPart
		}
	}

	fmt.Printf("┌────────────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│  vane send ─ Sending: %-44s │\n", util.TruncateStr(filepath.Base(filePath), 44))
	fmt.Printf("└────────────────────────────────────────────────────────────────────┘\n")
	fmt.Printf("  Connecting to peer %s...\033[K", targetAddr)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Printf(" Failed!\n")
		return fmt.Errorf("failed to connect to receiver: %w", err)
	}
	fmt.Printf(" Connected!\n")

	// Upgrade to TLS with untrusted verification
	// InsecureSkipVerify is safe here: self-signed cert + HMAC auth makes CA verification redundant
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn := tls.Client(rawConn, config)
	defer func() { _ = conn.Close() }()

	err = conn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// 1. Authenticate with TLS exporter + HMAC
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial("vane-p2p-auth", nil, 32)
	if err != nil {
		return fmt.Errorf("failed to extract TLS exporter material: %w", err)
	}

	senderHMAC := computeHMAC(cleanCode, exporter)
	_, err = conn.Write(senderHMAC)
	if err != nil {
		return fmt.Errorf("failed to send authorization key: %w", err)
	}

	var authResult [1]byte
	_, err = io.ReadFull(conn, authResult[:])
	if err != nil {
		return fmt.Errorf("failed to read authorization status: %w", err)
	}

	if authResult[0] != 1 {
		return fmt.Errorf("cryptographic pairing authentication failed (invalid code or session compromised)")
	}
	fmt.Printf("  Key Exchange: Cryptographically Authenticated ✓\n")

	// 2. Write file metadata
	filename := filepath.Base(filePath)
	fnBytes := []byte(filename)

	var fnLenBuf [2]byte
	binary.BigEndian.PutUint16(fnLenBuf[:], uint16(len(fnBytes)))
	_, _ = conn.Write(fnLenBuf[:])
	_, _ = conn.Write(fnBytes)

	var szBuf [8]byte
	binary.BigEndian.PutUint64(szBuf[:], uint64(fileSize))
	_, _ = conn.Write(szBuf[:])

	// 3. Stream file while hashing on-the-fly
	fmt.Printf("  File Size:  %.2f MB\n", float64(fileSize)/(1024*1024))
	startTime := time.Now()

	pr := &progressReader{
		src:       file,
		total:     fileSize,
		startTime: startTime,
	}

	sendHash := sha256.New()
	mw := io.MultiWriter(conn, sendHash)

	_, err = io.Copy(mw, pr)
	if err != nil {
		fmt.Printf("\n")
		return fmt.Errorf("failed during file streaming: %w", err)
	}
	fmt.Printf("\n")

	// 4. Verify integrity checksum with peer
	var recvHash [32]byte
	_, err = io.ReadFull(conn, recvHash[:])
	if err != nil {
		return fmt.Errorf("failed to read receiver checksum: %w", err)
	}

	localChecksum := sendHash.Sum(nil)
	fmt.Printf(" ────────────────────────────────────────────────────────────────────\n")
	if hmac.Equal(localChecksum, recvHash[:]) {
		fmt.Printf("  Integrity Verified: SHA-256 Checksum Match ✓\n")
		fmt.Printf("  Hash: %x\n", localChecksum)
	} else {
		return fmt.Errorf("INTEGRITY ERROR: SHA-256 Checksums do not match! File may be corrupted")
	}

	return nil
}
