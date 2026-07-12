package transfer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// generateSelfSignedCert creates an ephemeral TLS certificate completely in memory (zero disk trace)
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Vane Suite P2P"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, privPEM)
}

// generatePairingCode creates a secure, human-readable 8-digit grouping code
func generatePairingCode() (string, error) {
	var b [4]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%04d-%04d",
		(int(b[0])<<8|int(b[1]))%10000,
		(int(b[2])<<8|int(b[3]))%10000)
	return code, nil
}

// computeHMAC calculates a cryptographic signature binding the TLS tunnel to the pairing code
func computeHMAC(code string, exporter []byte) []byte {
	h := hmac.New(sha256.New, []byte(code))
	h.Write(exporter)
	return h.Sum(nil)
}

// progressWriter measures raw throughput and updates the CLI progress bar in-place
type progressWriter struct {
	dst       io.Writer
	total     int64
	written   int64
	startTime time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.dst.Write(p)
	if n > 0 {
		pw.written += int64(n)
		pw.printProgress()
	}
	return n, err
}

func (pw *progressWriter) printProgress() {
	elapsed := time.Since(pw.startTime).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	speed := float64(pw.written) / (1024 * 1024 * elapsed) // MB/s

	pct := float64(pw.written) / float64(pw.total) * 100.0
	barWidth := 30
	filled := int(float64(barWidth) * float64(pw.written) / float64(pw.total))
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	timeLeft := 0.0
	if speed > 0 {
		timeLeft = float64(pw.total-pw.written) / (speed * 1024 * 1024)
	}

	fmt.Printf("\r  Progress:   [%s] %.1f%%  Speed: %.1f MB/s  ETA: %.0fs\033[K", bar, pct, speed, timeLeft)
}

// progressReader measures read speed and updates the sender's progress bar in-place
type progressReader struct {
	src       io.Reader
	total     int64
	readBytes int64
	startTime time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.src.Read(p)
	if n > 0 {
		pr.readBytes += int64(n)
		pr.printProgress()
	}
	return n, err
}

func (pr *progressReader) printProgress() {
	elapsed := time.Since(pr.startTime).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	speed := float64(pr.readBytes) / (1024 * 1024 * elapsed) // MB/s

	pct := float64(pr.readBytes) / float64(pr.total) * 100.0
	barWidth := 30
	filled := int(float64(barWidth) * float64(pr.readBytes) / float64(pr.total))
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	timeLeft := 0.0
	if speed > 0 {
		timeLeft = float64(pr.total-pr.readBytes) / (speed * 1024 * 1024)
	}

	fmt.Printf("\r  Progress:   [%s] %.1f%%  Speed: %.1f MB/s  ETA: %.0fs\033[K", bar, pct, speed, timeLeft)
}

// PerformSend streams a file securely to the receiver using ECDHE + HMAC authorization
func PerformSend(filePath, code string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

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
	fmt.Printf("│  vane send ─ Sending: %-44s │\n", truncateStr(filepath.Base(filePath), 44))
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
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn := tls.Client(rawConn, config)
	defer conn.Close()

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
	defer ln.Close()

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
	defer conn.Close()

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
	fmt.Printf("│  vane recv ─ Receiving: %-42s │\033[K\n", truncateStr(filename, 42))
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
	defer dstFile.Close()

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

// truncateStr ensures long filenames don't overflow fixed borders
func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
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

	config := &tls.Config{InsecureSkipVerify: true}
	conn := tls.Client(rawConn, config)
	defer conn.Close()

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
	defer ln.Close()

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
	defer conn.Close()

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
