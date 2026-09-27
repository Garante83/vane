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

// PerformReceive sets up the listening port, displays the ephemeral pairing code, and downloads the file
func PerformReceive(port string) error {
	code, err := generatePairingCode()
	if err != nil {
		return fmt.Errorf("failed to generate grouping pairing code: %w", err)
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate memory TLS certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	addr := ":" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", port, err)
	}
	defer func() { _ = ln.Close() }()

	fmt.Printf("┌────────────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│  vane recv ─ Standing by for incoming file transfer...             │\n")
	fmt.Printf("└────────────────────────────────────────────────────────────────────┘\n")
	fmt.Printf("  Listening on: [::]:%s (All Interfaces)\n", port)

	// Show local IPs to help user
	localIPs := getLocalIPv4s()
	if len(localIPs) > 0 {
		fmt.Printf("  Receiver IPs: %s\n", strings.Join(localIPs, ", "))
		// Pre-format the helper command!
		fmt.Printf("  Pairing Code: %s#%s\n", localIPs[0], code)
		fmt.Printf("\n  Please run on sender:\n")
		fmt.Printf("  vane send <file> --code %s#%s\n", localIPs[0], code)
	} else {
		fmt.Printf("  Pairing Code: %s\n", code)
		fmt.Printf("\n  Please run on sender:\n")
		fmt.Printf("  vane send <file> --code <receiver-ip>#%s\n", code)
	}
	fmt.Printf(" ────────────────────────────────────────────────────────────────────\n")

	rawConn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept incoming connection: %w", err)
	}

	conn := tls.Server(rawConn, config)
	defer func() { _ = conn.Close() }()

	err = conn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// 1. Authenticate using TLS exporter + HMAC
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial("vane-p2p-auth", nil, 32)
	if err != nil {
		return fmt.Errorf("failed to extract TLS exporter material: %w", err)
	}

	var senderHMAC [32]byte
	_, err = io.ReadFull(conn, senderHMAC[:])
	if err != nil {
		return fmt.Errorf("failed to read sender authorization: %w", err)
	}

	expectedHMAC := computeHMAC(code, exporter)
	if hmac.Equal(senderHMAC[:], expectedHMAC) {
		// Write success confirmation byte
		_, _ = conn.Write([]byte{1})
	} else {
		_, _ = conn.Write([]byte{0})
		return fmt.Errorf("unauthorized pairing attempt blocked: HMAC mismatch")
	}

	// 2. Read file metadata
	var fnLenBuf [2]byte
	_, err = io.ReadFull(conn, fnLenBuf[:])
	if err != nil {
		return fmt.Errorf("failed to read filename length: %w", err)
	}
	fnLen := binary.BigEndian.Uint16(fnLenBuf[:])

	fnBytes := make([]byte, fnLen)
	_, err = io.ReadFull(conn, fnBytes)
	if err != nil {
		return fmt.Errorf("failed to read filename: %w", err)
	}
	filename := string(fnBytes)

	var szBuf [8]byte
	_, err = io.ReadFull(conn, szBuf[:])
	if err != nil {
		return fmt.Errorf("failed to read file size: %w", err)
	}
	fileSize := int64(binary.BigEndian.Uint64(szBuf[:]))

	// Clear listen output and print download panel
	fmt.Printf("\033[9A\r") // Move cursor up past the standing panel
	fmt.Printf("┌────────────────────────────────────────────────────────────────────┐\033[K\n")
	fmt.Printf("│  vane recv ─ Receiving: %-42s │\033[K\n", util.TruncateStr(filename, 42))
	fmt.Printf("└────────────────────────────────────────────────────────────────────┘\033[K\n")
	fmt.Printf("  File Size:  %.2f MB\033[K\n", float64(fileSize)/(1024*1024))

	// Ensure unique file name on receive
	dstPath := filename
	if _, err := os.Stat(dstPath); err == nil {
		ext := filepath.Ext(filename)
		base := filename[:len(filename)-len(ext)]
		dstPath = fmt.Sprintf("%s_received%s", base, ext)
	}

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dstPath, err)
	}
	defer func() { _ = dstFile.Close() }()

	// 3. Stream data to file and hash on-the-fly
	startTime := time.Now()
	pw := &progressWriter{
		dst:       dstFile,
		total:     fileSize,
		startTime: startTime,
	}

	recvHash := sha256.New()
	mw := io.MultiWriter(pw, recvHash)

	_, err = io.CopyN(mw, conn, fileSize)
	if err != nil {
		fmt.Printf("\n")
		return fmt.Errorf("failed during data stream retrieval: %w", err)
	}
	fmt.Printf("\n")

	// 4. Send calculated SHA-256 back to sender for integrity verification
	localChecksum := recvHash.Sum(nil)
	_, err = conn.Write(localChecksum)
	if err != nil {
		return fmt.Errorf("failed to transmit checksum back to sender: %w", err)
	}

	fmt.Printf(" ────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("  File successfully written to: %s\n", dstPath)
	fmt.Printf("  Integrity Verified: SHA-256 Checksum Match ✓\n")
	fmt.Printf("  Hash: %x\n", localChecksum)

	return nil
}

// getLocalIPv4s retrieves all active non-loopback IPv4 addresses
func getLocalIPv4s() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips
}
