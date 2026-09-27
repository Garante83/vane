// Package transfer implements zero-config, peer-to-peer encrypted file
// transfers (vane send / recv). Sessions use ephemeral TLS 1.3 with ECDHE,
// session-bound HMAC pairing codes and parallel SHA-256 integrity checks.
// It also supports registry-based cache exchange between peers.
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
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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

// Write forwards bytes to the underlying writer while counting throughput
// and refreshing the CLI progress bar (implements io.Writer).
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

// Read pulls bytes from the underlying reader while counting throughput
// and refreshing the CLI progress bar (implements io.Reader).
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
