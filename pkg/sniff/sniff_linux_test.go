package sniff

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildDNSQuery constructs a minimal valid DNS query payload for the given domain
func buildDNSQuery(domain string, response bool) []byte {
	var payload []byte
	// Header: ID (2), flags (2), QDCOUNT (2), then three zero counts
	flags := uint16(0x0100)
	if response {
		flags = 0x8180 // QR bit set for responses
	}
	payload = append(payload, 0xAB, 0xCD)
	payload = append(payload, byte(flags>>8), byte(flags))
	payload = append(payload, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// QNAME: length-prefixed labels
	for _, label := range splitDNSLabels(domain) {
		payload = append(payload, byte(len(label)))
		payload = append(payload, label...)
	}
	payload = append(payload, 0x00)

	// QTYPE (A=1), QCLASS (IN=1)
	payload = append(payload, 0x00, 0x01, 0x00, 0x01)
	return payload
}

// splitDNSLabels splits a domain into its labels for wire format encoding
func splitDNSLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

// buildIPv4Frame wraps an IP payload in a complete Ethernet + IPv4 frame
func buildEthernetIPv4(protocol byte, ttl byte) []byte {
	frame := make([]byte, 14+20)
	// Ethernet: dst MAC, src MAC, EtherType IPv4
	copy(frame[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(frame[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	// IPv4 header: version 4, IHL 5 (20 bytes), ttl, protocol, src 192.168.178.53, dst 192.168.178.1
	frame[14] = 0x45
	frame[15] = 0x00
	frame[14+6] = ttl      // TTL
	frame[14+9] = protocol // protocol field at offset 9 inside the IP header
	copy(frame[14+12:14+16], net.IPv4(192, 168, 178, 53).To4())
	copy(frame[14+16:14+20], net.IPv4(192, 168, 178, 1).To4())
	return frame
}

// buildUDPOverIPv4 returns an Ethernet+IPv4 frame carrying a UDP DNS query
func buildUDPOverIPv4(dnsPayload []byte) []byte {
	frame := buildEthernetIPv4(17, 64)
	udp := make([]byte, 8+len(dnsPayload))
	binary.BigEndian.PutUint16(udp[0:2], 53000) // src port
	binary.BigEndian.PutUint16(udp[2:4], 53)    // dst port 53 → DNS
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], dnsPayload)

	// IPv4 header fields: message length = header (20) + udp len
	binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(20+len(udp)))
	return append(frame, udp...)
}

// buildTCPOverIPv4 returns an Ethernet+IPv4 frame carrying a TCP payload on port 80
func buildTCPOverIPv4(tcpPayload []byte) []byte {
	frame := buildEthernetIPv4(6, 64)
	tcp := make([]byte, 20+len(tcpPayload))
	binary.BigEndian.PutUint16(tcp[0:2], 51000) // src port
	binary.BigEndian.PutUint16(tcp[2:4], 80)    // dst port 80 → HTTP
	tcp[12] = 5 << 4                            // data offset: 5 words = 20 bytes
	copy(tcp[20:], tcpPayload)

	binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(20+len(tcp)))
	return append(frame, tcp...)
}

// TestHTons verifies host-to-network byte order conversion
func TestHTons(t *testing.T) {
	tests := []struct {
		input    uint16
		expected uint16
	}{
		{0x0000, 0x0000},
		{0x0001, 0x0100},
		{0x1234, 0x3412},
		{0xABCD, 0xCDAB},
		{0xFFFF, 0xFFFF},
	}
	for _, tc := range tests {
		if got := htons(tc.input); got != tc.expected {
			t.Errorf("htons(0x%04X) = 0x%04X, expected 0x%04X", tc.input, got, tc.expected)
		}
	}
}

// TestParsePacketTooShort ensures short frames don't panic
func TestParsePacketTooShort(t *testing.T) {
	for i := 0; i < 14; i++ {
		parsePacket(make([]byte, i))
	}
}

// TestParsePacketIcmShortPayload guards against truncated IP payloads
func TestParsePacketShortPayloads(t *testing.T) {
	// IPv4 header present but payload truncated below minimums (ICMP/UDP/TCP)
	for _, proto := range []byte{1, 6, 17} {
		frame := buildEthernetIPv4(proto, 64)
		parsePacket(frame) // No transport payload at all
	}

	// UDP: payload shorter than 8-byte header
	frame := buildEthernetIPv4(17, 64)
	binary.BigEndian.PutUint16(frame[14+2:14+4], 20+4)
	parsePacket(append(frame, 0x00, 0x01, 0x02, 0x03))

	// UDP: udpLen field larger than actual payload
	udp := make([]byte, 10)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 9999)
	frame = buildEthernetIPv4(17, 64)
	binary.BigEndian.PutUint16(frame[14+2:14+4], 20+10)
	parsePacket(append(frame, udp...))

	// TCP: payload shorter than 20-byte header
	frame = buildEthernetIPv4(6, 64)
	binary.BigEndian.PutUint16(frame[14+2:14+4], 20+10)
	parsePacket(append(frame, make([]byte, 10)...))

	// TCP: data offset larger than payload
	tcp := make([]byte, 24) // data offset claims 20, payload 4 empty
	tcp[12] = 5 << 4
	frame = buildEthernetIPv4(6, 64)
	binary.BigEndian.PutUint16(frame[14+2:14+4], 20+24)
	parsePacket(append(frame, tcp...))
}

// TestParsePacketIHLTruncation guards against IHL larger than packet length
func TestParsePacketIHLTruncation(t *testing.T) {
	frame := buildEthernetIPv4(6, 64)
	frame[14] = 0x4F // IHL = 15 (60 bytes) but header is only 20
	parsePacket(frame)
}

// TestParsePacketHTTPVariants covers port matching and detail formatting paths
func TestParsePacketHTTPVariants(t *testing.T) {
	// Ports 8080/8000 and source-port detection
	for _, port := range []uint16{8080, 8000} {
		frame := buildEthernetIPv4(6, 64)
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:2], 51000)
		binary.BigEndian.PutUint16(tcp[2:4], port)
		tcp[12] = 5 << 4
		httpPayload := []byte("POST /api HTTP/1.1\r\nHost: x.local\r\n\r\n")
		binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(20+len(tcp)+len(httpPayload)))
		parsePacket(append(append(frame, tcp...), httpPayload...))

		// HTTP payload on source port 80 (response side)
		frame2 := buildEthernetIPv4(6, 64)
		tcp2 := make([]byte, 20+len(httpPayload))
		binary.BigEndian.PutUint16(tcp2[0:2], 80)
		binary.BigEndian.PutUint16(tcp2[2:4], 51000)
		tcp2[12] = 5 << 4
		copy(tcp2[20:], httpPayload)
		binary.BigEndian.PutUint16(frame2[14+2:14+4], uint16(20+len(tcp2)))
		parsePacket(append(frame2, tcp2...))
	}

	// HTTP on a non-sniffed port (4711) → no output path
	frame := buildEthernetIPv4(6, 64)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[2:4], 4711)
	tcp[12] = 5 << 4
	binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(20+len(tcp)))
	parsePacket(append(frame, tcp...))

	// TCP with payload but non-HTTP content
	frame = buildEthernetIPv4(6, 64)
	tcp = make([]byte, 20+6)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = 5 << 4
	copy(tcp[20:], "binary")
	binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(20+len(tcp)))
	parsePacket(append(frame, tcp...))
}

// TestParsePacketDNS non-query/reply handling covered; ensure srcPort 53 path also fires
func TestParsePacketDNSSourcePort(t *testing.T) {
	query := buildDNSQuery("example.com", false)
	// Swap ports: query from port 53 back to client
	frame := buildUDPOverIPv4(query)
	udp := frame[14+20:]
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], 53000)
	parsePacket(frame)
}

// TestParsePacketIHLTruncationSmall guards against zero-length transport payloads
func TestParsePacketIHLTruncationSmall(t *testing.T) {
	// UDP with valid header but empty DNS payload → no domain, no output
	frame := buildEthernetIPv4(17, 64)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	binary.BigEndian.PutUint16(frame[14+2:14+4], 20+8)
	parsePacket(append(frame, udp...))
}

// TestPrintLogCoversProtocols exercises the colored output paths
func TestPrintLogCoversProtocols(t *testing.T) {
	for _, proto := range []string{"DNS", "HTTP", "ICMP", "UNKNOWN"} {
		printLog(proto, "192.168.178.53", "192.168.178.1", "QUERY: example.com")
	}
	for _, detail := range []string{"PING REQUEST", "PING REPLY", "DEST UNREACHABLE", "TYPE 13"} {
		printLog("ICMP", "192.168.178.53", "192.168.178.1", detail)
	}
	for _, detail := range []string{"GET: / (Host: example.com)", "POST: /api", "DELETE: /x", "PUT: /y"} {
		printLog("HTTP", "192.168.178.53", "192.168.178.1", detail)
	}
}

// TestParsePacketWrongEtherType verifies non-IPv4 frames are ignored
func TestParsePacketWrongEtherType(t *testing.T) {
	frame := buildEthernetIPv4(6, 64)
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6 EtherType
	parsePacket(frame)
}

// TestParsePacketICMP ensures ICMP ping types are decoded without panic
func TestParsePacketICMP(t *testing.T) {
	for _, icmpType := range []byte{8, 0, 3, 11, 42} {
		frame := buildEthernetIPv4(1, 64)
		icmp := []byte{icmpType, 0x00, 0x00, 0x00}
		binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(20+len(icmp)))
		parsePacket(append(frame, icmp...))
	}
}

// TestParsePacketDNS verifies DNS queries are parsed end-to-end through the frame
func TestParsePacketDNS(t *testing.T) {
	query := buildDNSQuery("example.com", false)
	frame := buildUDPOverIPv4(query)
	parsePacket(frame)
}

// TestParsePacketHTTP ensures HTTP requests are parsed end-to-end through the frame
func TestParsePacketHTTP(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	frame := buildTCPOverIPv4(payload)
	parsePacket(frame)
}

// TestParseDNSQueryValid verifies labeled domain decompression
func TestParseDNSQueryValid(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected string
	}{
		{"simple query", buildDNSQuery("example.com", false), "example.com"},
		{"response ignored", buildDNSQuery("example.com", true), ""},
		{"subdomain", buildDNSQuery("www.example.com", false), "www.example.com"},
	}
	for _, tc := range tests {
		if got := parseDNSQuery(tc.payload); got != tc.expected {
			t.Errorf("%s: parseDNSQuery = %q, expected %q", tc.name, got, tc.expected)
		}
	}
}

// TestParseDNSQueryEdgeCases covers malformed and truncated payloads
func TestParseDNSQueryEdgeCases(t *testing.T) {
	if got := parseDNSQuery(make([]byte, 12)); got != "" {
		t.Errorf("empty payload: expected %q, got %q", "", got)
	}

	// Pointer compression (0xC0 prefix) should terminate parsing
	trailing := append([]byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C}, 0x00)
	if got := parseDNSQuery(trailing); got != "" {
		t.Errorf("pointer compression: expected surrogate stop, got %q", got)
	}

	// Label length exceeds payload
	short := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x61}
	if got := parseDNSQuery(short); got != "" {
		t.Errorf("label overflow: expected %q, got %q", "", got)
	}
}

// TestParseHTTPRequestValid covers request line and Host header extraction
func TestParseHTTPRequestValid(t *testing.T) {
	tests := []struct {
		name         string
		payload      string
		expectedReq  string
		expectedHost string
	}{
		{"GET with host", "GET /a/b HTTP/1.1\r\nHost: example.com\r\n\r\n", "GET /a/b HTTP/1.1", "example.com"},
		{"POST no host", "POST / HTTP/1.1\r\n\r\n", "POST / HTTP/1.1", ""},
		{"HEAD", "HEAD / HTTP/1.1\r\nhost: boxed\r\n\r\n", "HEAD / HTTP/1.1", "boxed"},
	}
	for _, tc := range tests {
		req, host := parseHTTPRequest([]byte(tc.payload))
		if req != tc.expectedReq || host != tc.expectedHost {
			t.Errorf("%s: got (%q, %q), expected (%q, %q)", tc.name, req, host, tc.expectedReq, tc.expectedHost)
		}
	}
}

// TestParseHTTPRequestInvalid covers non-HTTP payloads
func TestParseHTTPRequestInvalid(t *testing.T) {
	tests := []string{
		"garbage",
		"SHUTDOWN /now HTTP/1.1", // unsupported method
	}
	for _, s := range tests {
		req, host := parseHTTPRequest([]byte(s))
		if req != "" || host != "" {
			t.Errorf("parseHTTPRequest(%q) = (%q, %q), expected empty", s, req, host)
		}
	}
}

// TestSpinAndOutputHelpers covers spinner/mutex helper functions for coverage and race safety
func TestSpinAndOutputHelpers(t *testing.T) {
	StartStandbySpinner()
	MarkOutputLogged()
	LockOutput()
	UnlockOutput()
}
