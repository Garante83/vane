package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"vane/pkg/netstate"
	"vane/pkg/sniff"
	"vane/pkg/transfer"
	"vane/pkg/uip"
)

// runSendSubcommand implements the 'vane send <file> --code <code>' argument extraction.
func runSendSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "[vane] Error: File path expected to send (e.g. vane send backup.tar.gz)")
		os.Exit(1)
	}
	filePath := args[0]

	code := ""
	for i := 1; i < len(args)-1; i++ {
		if args[i] == "--code" || args[i] == "-c" {
			code = args[i+1]
			break
		}
	}

	if code == "" {
		fmt.Fprintln(os.Stderr, "[vane] Error: One-time pairing code expected (e.g. vane send backup.tar.gz --code 7392-1845)")
		os.Exit(1)
	}

	err := transfer.PerformSend(filePath, code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// runRecvSubcommand implements the 'vane recv [--port <port>]' argument extraction.
func runRecvSubcommand(args []string) {
	port := "8484"
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--port" || args[i] == "-p" {
			port = args[i+1]
			break
		}
	}

	err := transfer.PerformReceive(port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// runSniffSubcommand implements the 'vane sniff [interface]' argument extraction
// and starts the platform-specific traffic capture.
func runSniffSubcommand(args []string) {
	ifaceName := ""
	if len(args) >= 1 {
		ifaceName = args[0]
		if t, isVane := uip.ExtractToken(ifaceName); isVane {
			ifaceName = t.Interface
		}
	} else {
		ifaceName = getDefaultActiveInterface()
	}

	if ifaceName == "" && runtime.GOOS == "linux" {
		fmt.Fprintln(os.Stderr, "[vane] Error: No active network interface with a valid IPv4 address found to sniff.")
		os.Exit(1)
	}

	// Resolve alias/index to real name if passed (e.g. "1" -> "eno1")
	if ifaceName != "" {
		state, err := netstate.GetInterfaceState(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		ifaceName = state.InterfaceName
	}

	err := sniff.PerformSniff(ifaceName)
	if err != nil {
		if errors.Is(err, sniff.ErrReexec) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
