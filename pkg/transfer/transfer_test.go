package transfer

import (
	"regexp"
	"testing"
)

func TestGeneratePairingCode(t *testing.T) {
	code, err := generatePairingCode()
	if err != nil {
		t.Fatalf("failed to generate pairing code: %v", err)
	}

	// Verification of pairing code syntax: "XXXX-XXXX"
	matched, err := regexp.MatchString(`^\d{4}-\d{4}$`, code)
	if err != nil {
		t.Fatalf("regex comparison failed: %v", err)
	}
	if !matched {
		t.Errorf("pairing code %q did not match expected syntax pattern XXXX-XXXX", code)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate in-memory TLS cert: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Errorf("generated certificate contains 0 block chains")
	}
	if cert.PrivateKey == nil {
		t.Errorf("generated memory private key is nil")
	}
}

func TestComputeHMAC(t *testing.T) {
	code := "1234-5678"
	exporter := []byte("vane-p2p-auth-test-exporter-material")
	sig1 := computeHMAC(code, exporter)
	sig2 := computeHMAC(code, exporter)

	if len(sig1) != 32 {
		t.Errorf("expected 32-byte HMAC signature payload, got %d bytes", len(sig1))
	}
	for i := range sig1 {
		if sig1[i] != sig2[i] {
			t.Fatalf("HMAC signature generation is non-deterministic")
		}
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{input: "short", maxLen: 10, expected: "short"},
		{input: "reallylongfilename.txt", maxLen: 12, expected: "reallylon..."},
	}

	for _, tc := range tests {
		res := truncateStr(tc.input, tc.maxLen)
		if res != tc.expected {
			t.Errorf("truncateStr(%q, %d) = %q, expected %q", tc.input, tc.maxLen, res, tc.expected)
		}
	}
}
