// Package sniff implements real-time traffic capture for HTTP requests and
// DNS queries. On Linux it uses raw AF_PACKET sockets with a pure-Go packet
// parser; on Windows it falls back to a PowerShell connection-to-process
// mapper. Unsupported platforms receive a descriptive stub error.
package sniff

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	writeMutex sync.Mutex
	hasOutput  bool
)

// ErrReexec indicates the process was re-executed with sudo; caller should exit.
var ErrReexec = errors.New("re-executed with sudo")

// StartStandbySpinner runs a background goroutine to display an active listening spinner.
// It stops displaying once a packet is logged.
func StartStandbySpinner() {
	go func() {
		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		idx := 0
		for {
			writeMutex.Lock()
			if hasOutput {
				writeMutex.Unlock()
				break
			}
			fmt.Printf("\r  %s Listening for incoming network packets...", spinner[idx])
			writeMutex.Unlock()

			idx = (idx + 1) % len(spinner)
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

// MarkOutputLogged sets the output flag so the spinner stops and clears itself cleanly.
func MarkOutputLogged() {
	writeMutex.Lock()
	defer writeMutex.Unlock()
	if !hasOutput {
		fmt.Print("\r\x1b[K") // Erase the spinner line cleanly
		hasOutput = true
	}
}

// LockOutput locks the print mutex to prevent overlapping console writes
func LockOutput() {
	writeMutex.Lock()
}

// UnlockOutput unlocks the print mutex
func UnlockOutput() {
	writeMutex.Unlock()
}
