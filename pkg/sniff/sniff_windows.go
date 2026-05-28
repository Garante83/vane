//go:build windows

package sniff

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// PerformSniff implements a live connection-to-process mapper on Windows
func PerformSniff(ifaceName string) error {
	fmt.Printf("┌────────────────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│  vane sniff ─ Active Connection Monitor (Windows Fallback)             │\n")
	fmt.Printf("└────────────────────────────────────────────────────────────────────────┘\n")
	fmt.Printf("  %-8s  %-5s  %-21s  %-21s  %s\n", "TIME", "PROTO", "LOCAL ADDRESS", "FOREIGN ADDRESS", "PROCESS (PID)")
	fmt.Printf(" ────────────────────────────────────────────────────────────────────────\n")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n ────────────────────────────────────────────────────────────────────────\n")
		fmt.Printf("  Monitoring stopped. Goodbye!\n")
		os.Exit(0)
	}()

	StartStandbySpinner()

	seen := make(map[string]bool)
	for {
		connections, err := getActiveWindowsConnections()
		if err == nil {
			timeStr := time.Now().Format("15:04:05")
			for _, conn := range connections {
				key := fmt.Sprintf("%s-%s-%s", conn.Proto, conn.Local, conn.Foreign)
				if !seen[key] {
					MarkOutputLogged()
					LockOutput()
					seen[key] = true
					fmt.Printf("  %-8s  %-5s  %-21s  %-21s  %s\n",
						timeStr, conn.Proto, conn.Local, conn.Foreign, truncateStr(conn.Process, 25))
					UnlockOutput()
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

type winConn struct {
	Proto   string
	Local   string
	Foreign string
	Process string
}

func getActiveWindowsConnections() ([]winConn, error) {
	cmdStr := `Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
		$proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
		$name = if ($proc) { $proc.Name } else { "System" }
		"$($_.LocalAddress):$($_.LocalPort)|$($_.RemoteAddress):$($_.RemotePort)|$name ($($_.OwningProcess))"
	}`

	cmd := exec.Command("powershell", "-Command", cmdStr)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var list []winConn
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		list = append(list, winConn{
			Proto:   "TCP",
			Local:   parts[0],
			Foreign: parts[1],
			Process: parts[2],
		})
	}
	return list, nil
}
