//go:build linux

package sniff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"vane/pkg/util"
)

// ErrReexec indicates the process was re-executed with sudo; caller should exit.
var ErrReexec = errors.New("re-executed with sudo")

// htons converts host byte order to network byte order
func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}

// PerformSniff sets up the raw packet capture loop on Linux
func PerformSniff(ifaceName string) error {
	// 1. Raw socket creation requires root privileges
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		if os.IsPermission(err) {
			// Check if sudo requires a password (non-interactive check)
			needsPassword := true
			checkCmd := exec.Command("sudo", "-n", "true")
			if errCheck := checkCmd.Run(); errCheck == nil {
				needsPassword = false
			}

			if needsPassword {
				if util.GetSystemLanguage() == "de" {
					fmt.Println("  \x1b[1;33m[!] root-Rechte für Packet Sniffing benötigt. Starte neu mit 'sudo'...\x1b[0m")
				} else {
					fmt.Println("  \x1b[1;33m[!] root privileges required for packet sniffing. Relaunching with 'sudo'...\x1b[0m")
				}
			}

			cmd := exec.Command("sudo", os.Args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			errRun := cmd.Run()
			if errRun != nil {
				return fmt.Errorf("sudo re-execution failed: %w", errRun)
			}
			return ErrReexec
		}
		return fmt.Errorf("failed to open raw socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	// 2. Bind raw socket directly to specified interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("network interface %s not found: %w", ifaceName, err)
	}

	sall := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	err = syscall.Bind(fd, sall)
	if err != nil {
		return fmt.Errorf("failed to bind socket to interface %s: %w", ifaceName, err)
	}

	// 3. Print premium visual header
	fmt.Printf("┌────────────────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│  vane sniff ─ Monitoring HTTP & DNS Traffic on %-23s │\n", ifaceName)
	fmt.Printf("└────────────────────────────────────────────────────────────────────────┘\n")
	fmt.Printf("  %-8s  %-5s  %-15s  %-15s  %s\n", "TIME", "PROTO", "SOURCE", "TARGET", "DETAIL")
	fmt.Printf(" ────────────────────────────────────────────────────────────────────────\n")

	// 4. Graceful termination handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n ────────────────────────────────────────────────────────────────────────\n")
		fmt.Printf("  Sniffing stopped. Goodbye!\n")
		os.Exit(0)
	}()

	StartStandbySpinner()

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		parsePacket(buf[:n])
	}
}

// parsePacket decodes Ethernet, IPv4, UDP (DNS) and TCP (HTTP) packets
func parsePacket(packet []byte) {
	if len(packet) < 14 {
		return
	}

	etherType := binary.BigEndian.Uint16(packet[12:14])
	if etherType != 0x0800 { // We only capture IPv4
		return
	}

	ipPacket := packet[14:]
	if len(ipPacket) < 20 {
		return
	}

	ihl := int(ipPacket[0]&0x0F) * 4
	protocol := ipPacket[9]
	srcIP := net.IP(ipPacket[12:16]).String()
	dstIP := net.IP(ipPacket[16:20]).String()

	if len(ipPacket) < ihl {
		return
	}
	payload := ipPacket[ihl:]

	// ICMP Decoder (Pings & Routes!)
	if protocol == 1 {
		if len(payload) >= 1 {
			icmpType := payload[0]
			detail := ""
			switch icmpType {
			case 8:
				detail = "PING REQUEST"
			case 0:
				detail = "PING REPLY"
			case 3:
				detail = "DEST UNREACHABLE"
			case 11:
				detail = "TIME EXCEEDED (TTL)"
			default:
				detail = fmt.Sprintf("TYPE %d", icmpType)
			}
			printLog("ICMP", srcIP, dstIP, detail)
		}
	}

	// UDP Decoder (DNS Queries)
	if protocol == 17 {
		if len(payload) < 8 {
			return
		}
		srcPort := binary.BigEndian.Uint16(payload[0:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		udpLen := binary.BigEndian.Uint16(payload[4:6])

		if len(payload) < int(udpLen) {
			return
		}
		udpPayload := payload[8:udpLen]

		if dstPort == 53 || srcPort == 53 {
			domain := parseDNSQuery(udpPayload)
			if domain != "" {
				printLog("DNS", srcIP, dstIP, fmt.Sprintf("QUERY: %s", domain))
			}
		}
	}

	// TCP Decoder (HTTP Request Sniffing)
	if protocol == 6 {
		if len(payload) < 20 {
			return
		}
		srcPort := binary.BigEndian.Uint16(payload[0:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		dataOffset := int(payload[12]>>4) * 4

		if len(payload) < dataOffset {
			return
		}
		tcpPayload := payload[dataOffset:]
		if len(tcpPayload) == 0 {
			return
		}

		// Sniff HTTP on common ports
		if dstPort == 80 || srcPort == 80 || dstPort == 8080 || srcPort == 8080 || dstPort == 8000 || srcPort == 8000 {
			reqLine, host := parseHTTPRequest(tcpPayload)
			if reqLine != "" {
				parts := strings.SplitN(reqLine, " ", 3)
				if len(parts) >= 2 {
					method := parts[0]
					path := parts[1]

					// Pad the method prefix (e.g. "GET:") to 7 characters to match "QUERY: " exactly
					methodLabel := fmt.Sprintf("%s:", method)
					prefix := fmt.Sprintf("%-7s", methodLabel)

					detail := ""
					if host != "" {
						detail = fmt.Sprintf("%s%s (Host: %s)", prefix, path, host)
					} else {
						detail = fmt.Sprintf("%s%s", prefix, path)
					}
					printLog("HTTP", srcIP, dstIP, detail)
				} else {
					printLog("HTTP", srcIP, dstIP, reqLine)
				}
			}
		}
	}
}

// parseDNSQuery decodes domain names in standard DNS query questions
func parseDNSQuery(payload []byte) string {
	if len(payload) < 13 {
		return ""
	}

	// Check if QR bit (query/response flag) is 0 (it is a query)
	qr := (payload[2] >> 7) & 1
	if qr != 0 {
		return ""
	}

	var sb strings.Builder
	idx := 12
	for idx < len(payload) {
		length := int(payload[idx])
		if length == 0 {
			break
		}
		// Pointer compression check
		if (length & 0xC0) == 0xC0 {
			break // Skip compression labels for query simplicity
		}
		if idx+1+length > len(payload) {
			return ""
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(payload[idx+1 : idx+1+length])
		idx += 1 + length
	}
	return sb.String()
}

// parseHTTPRequest extracts the HTTP request line and host header from TCP payloads
func parseHTTPRequest(payload []byte) (string, string) {
	s := string(payload)
	lines := strings.SplitN(s, "\r\n", 10)
	if len(lines) == 0 {
		return "", ""
	}

	reqLine := lines[0]
	isHTTP := false
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "} {
		if strings.HasPrefix(reqLine, method) {
			isHTTP = true
			break
		}
	}

	if !isHTTP {
		return "", ""
	}

	host := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}

	return reqLine, host
}

// printLog outputs a parsed request log perfectly formatted to standard widths
func printLog(proto, src, dst, detail string) {
	timeStr := time.Now().Format("15:04:05")

	// Apply layout-safe ANSI colors to protocol column
	coloredProto := proto
	switch proto {
	case "DNS":
		coloredProto = "\033[34mDNS\033[0m" // Blue
	case "HTTP":
		coloredProto = "\033[32mHTTP\033[0m" // Green
	case "ICMP":
		coloredProto = "\033[35mICMP\033[0m" // Magenta/Purple
	}

	// Pad protocol to exactly 5 characters to maintain alignment despite ANSI escape tags
	paddedProto := coloredProto
	switch proto {
	case "DNS":
		paddedProto = coloredProto + "  "
	case "HTTP", "ICMP":
		paddedProto = coloredProto + " "
	}

	// Truncate first to prevent cutting off color codes
	coloredDetail := util.TruncateStr(detail, 40)

	// Apply layout-safe ANSI colors to methods and query actions
	if strings.HasPrefix(coloredDetail, "QUERY:") {
		coloredDetail = "\033[36mQUERY:\033[0m" + coloredDetail[6:] // Cyan for DNS queries
	} else if strings.HasPrefix(coloredDetail, "GET:") {
		coloredDetail = "\033[32mGET:\033[0m" + coloredDetail[4:] // Green for GET requests
	} else if strings.HasPrefix(coloredDetail, "POST:") {
		coloredDetail = "\033[33mPOST:\033[0m" + coloredDetail[5:] // Yellow for POST requests
	} else if strings.HasPrefix(coloredDetail, "DELETE:") {
		coloredDetail = "\033[31mDELETE:\033[0m" + coloredDetail[7:] // Red for DELETE requests
	} else if strings.HasPrefix(coloredDetail, "PUT:") || strings.HasPrefix(coloredDetail, "PATCH:") {
		coloredDetail = "\033[35m" + strings.SplitN(coloredDetail, " ", 2)[0] + "\033[0m" + coloredDetail[strings.Index(coloredDetail, " "):] // Purple for PUT/PATCH
	} else if strings.HasPrefix(coloredDetail, "PING REQUEST") {
		coloredDetail = "\033[33mPING REQUEST\033[0m" // Yellow for ping requests
	} else if strings.HasPrefix(coloredDetail, "PING REPLY") {
		coloredDetail = "\033[32mPING REPLY\033[0m" // Green for ping replies
	} else if strings.HasPrefix(coloredDetail, "DEST UNREACHABLE") {
		coloredDetail = "\033[31mDEST UNREACHABLE\033[0m" // Red for errors
	}

	MarkOutputLogged()
	LockOutput()
	defer UnlockOutput()

	fmt.Printf("  %-8s  %s  %-15s  %-15s  %s\n", timeStr, paddedProto, src, dst, coloredDetail)
}
