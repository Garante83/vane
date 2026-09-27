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
	"strings"
	"time"
)

// PerformRegistrySend streams raw registry bytes securely to the receiver using ECDHE + HMAC authorization.
func PerformRegistrySend(registryData []byte, code string) error {
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

	fmt.Printf("  Connecting to peer %s...\n", targetAddr)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to receiver: %w", err)
	}

	// InsecureSkipVerify: self-signed cert + HMAC auth makes CA verification redundant
	config := &tls.Config{InsecureSkipVerify: true}
	conn := tls.Client(rawConn, config)
	defer func() { _ = conn.Close() }()

	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial("vane-p2p-auth", nil, 32)
	if err != nil {
		return fmt.Errorf("failed to extract TLS exporter material: %w", err)
	}

	senderHMAC := computeHMAC(cleanCode, exporter)
	if _, err := conn.Write(senderHMAC); err != nil {
		return fmt.Errorf("failed to send authorization key: %w", err)
	}

	var authResult [1]byte
	if _, err := io.ReadFull(conn, authResult[:]); err != nil {
		return fmt.Errorf("failed to read authorization status: %w", err)
	}

	if authResult[0] != 1 {
		return fmt.Errorf("cryptographic pairing authentication failed (invalid code)")
	}
	fmt.Printf("  Key Exchange: Cryptographically Authenticated ✓\n")

	filename := "vssd-registry.json"
	fnBytes := []byte(filename)
	var fnLenBuf [2]byte
	binary.BigEndian.PutUint16(fnLenBuf[:], uint16(len(fnBytes)))
	_, _ = conn.Write(fnLenBuf[:])
	_, _ = conn.Write(fnBytes)

	dataSize := len(registryData)
	var szBuf [8]byte
	binary.BigEndian.PutUint64(szBuf[:], uint64(dataSize))
	_, _ = conn.Write(szBuf[:])

	sendHash := sha256.New()
	mw := io.MultiWriter(conn, sendHash)
	if _, err := mw.Write(registryData); err != nil {
		return fmt.Errorf("failed to write registry data: %w", err)
	}

	var recvHash [32]byte
	if _, err := io.ReadFull(conn, recvHash[:]); err != nil {
		return fmt.Errorf("failed to read receiver checksum: %w", err)
	}

	localChecksum := sendHash.Sum(nil)
	if !hmac.Equal(localChecksum, recvHash[:]) {
		return fmt.Errorf("INTEGRITY ERROR: SHA-256 Checksums do not match")
	}
	fmt.Printf("  Registry successfully exported and synchronized ✓\n")
	return nil
}

// PerformRegistryReceive sets up the listening port, displays the ephemeral pairing code, and downloads the raw registry data.
func PerformRegistryReceive(port string) ([]byte, error) {
	code, err := generatePairingCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pairing code: %w", err)
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %s: %w", port, err)
	}
	defer func() { _ = ln.Close() }()

	fmt.Printf("\n  🚀 VSSD Mirror Service Active!\n")
	fmt.Printf("  ────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("  Listening on: [::]:%s (All Interfaces)\n", port)

	localIPs := getLocalIPv4s()
	if len(localIPs) > 0 {
		fmt.Printf("  Pairing Code: %s#%s\n", localIPs[0], code)
		fmt.Printf("\n  Please run on sender:\n")
		fmt.Printf("  vane discover --export --code %s#%s\n", localIPs[0], code)
	} else {
		fmt.Printf("  Pairing Code: %s\n", code)
		fmt.Printf("\n  Please run on sender:\n")
		fmt.Printf("  vane discover --export --code <receiver-ip>#%s\n", code)
	}
	fmt.Printf("  ────────────────────────────────────────────────────────────────────\n")

	rawConn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}

	conn := tls.Server(rawConn, config)
	defer func() { _ = conn.Close() }()

	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial("vane-p2p-auth", nil, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TLS exporter material: %w", err)
	}

	var senderHMAC [32]byte
	if _, err := io.ReadFull(conn, senderHMAC[:]); err != nil {
		return nil, fmt.Errorf("failed to read sender authorization: %w", err)
	}

	expectedHMAC := computeHMAC(code, exporter)
	if hmac.Equal(senderHMAC[:], expectedHMAC) {
		_, _ = conn.Write([]byte{1})
	} else {
		_, _ = conn.Write([]byte{0})
		return nil, fmt.Errorf("unauthorized pairing attempt blocked")
	}

	var fnLenBuf [2]byte
	if _, err := io.ReadFull(conn, fnLenBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read filename length: %w", err)
	}
	fnLen := binary.BigEndian.Uint16(fnLenBuf[:])

	fnBytes := make([]byte, fnLen)
	if _, err := io.ReadFull(conn, fnBytes); err != nil {
		return nil, fmt.Errorf("failed to read filename: %w", err)
	}

	var szBuf [8]byte
	if _, err := io.ReadFull(conn, szBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read size: %w", err)
	}
	dataSize := int64(binary.BigEndian.Uint64(szBuf[:]))

	registryData := make([]byte, dataSize)
	recvHash := sha256.New()
	mw := io.MultiWriter(recvHash)

	// Read in chunks
	var totalRead int64
	for totalRead < dataSize {
		chunkSize := int64(4096)
		if dataSize-totalRead < chunkSize {
			chunkSize = dataSize - totalRead
		}
		buf := make([]byte, chunkSize)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read registry chunk: %w", err)
		}
		if n == 0 {
			break
		}
		copy(registryData[totalRead:totalRead+int64(n)], buf[:n])
		_, _ = mw.Write(buf[:n])
		totalRead += int64(n)
	}

	localChecksum := recvHash.Sum(nil)
	if _, err := conn.Write(localChecksum); err != nil {
		return nil, fmt.Errorf("failed to send checksum: %w", err)
	}

	return registryData, nil
}
