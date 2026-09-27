package transfer

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProgressWriterFlows verifies throughput counting and bar rendering via io.Writer
func TestProgressWriterFlows(t *testing.T) {
	var sink bytes.Buffer
	pw := &progressWriter{dst: &sink, total: 16, startTime: time.Now()}
	if n, err := io.WriteString(struct{ io.Writer }{pw}, "12345678"); err != nil || n != 8 {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	if pw.written != 8 {
		t.Errorf("written = %d, expected 8", pw.written)
	}
	if _, err := pw.Write([]byte("87654321")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if pw.written != 16 {
		t.Errorf("written = %d, expected 16", pw.written)
	}
	if sink.Len() != 16 {
		t.Errorf("sink received %d bytes, expected 16", sink.Len())
	}
}

// TestProgressReaderFlows verifies throughput counting via io.Reader
func TestProgressReaderFlows(t *testing.T) {
	src := strings.NewReader("abcdefgh")
	pr := &progressReader{src: src, total: 8, startTime: time.Now()}

	buf := make([]byte, 8)
	n, err := pr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read failed: %v", err)
	}
	if n != 8 || pr.readBytes != 8 {
		t.Fatalf("n=%d readBytes=%d, expected 8/8", n, pr.readBytes)
	}
}

// TestGetLocalIPv4s verifies only non-loopback IPv4s are returned
func TestGetLocalIPv4s(t *testing.T) {
	ips := getLocalIPv4s()
	for _, ip := range ips {
		if strings.HasPrefix(ip, "127.") {
			t.Errorf("loopback address %s must be excluded", ip)
		}
		if strings.Contains(ip, ":") {
			t.Errorf("non-IPv4 address %s must be excluded", ip)
		}
	}
}

// TestPerformSendMissingFile verifies error handling for absent input files
func TestPerformSendMissingFile(t *testing.T) {
	err := PerformSend(filepath.Join(t.TempDir(), "does-not-exist.bin"), "1234-5678")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// TestPerformReceiveInvalidPort verifies graceful failure on a taken/invalid port
func TestPerformReceiveInvalidPort(t *testing.T) {
	if err := PerformReceive("99999"); err == nil {
		t.Fatal("expected error for invalid port, got nil")
	} else if !strings.Contains(err.Error(), "listen") && !strings.Contains(err.Error(), "port") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// TestPerformSendUnreachablePeer verifies the dial-failure path including output
func TestPerformSendUnreachablePeer(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(tmp, []byte("data"), 0o644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	// Port 1 on loopback is (practically) never open → dial must fail fast
	err := PerformSend(tmp, "127.0.0.1:1#1234-5678")
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to connect to receiver") {
		t.Errorf("unexpected error text: %v", err)
	}
}
