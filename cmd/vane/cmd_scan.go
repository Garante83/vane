package main

import (
	"errors"
	"fmt"
	"os"

	"vane/pkg/netstate"
	"vane/pkg/scan"
	"vane/pkg/uip"
)

// runScanSubcommand implements the 'vane scan [interface]' argument extraction
// and hands off to the subnet sweeper.
func runScanSubcommand(args []string) {
	ifaceName := ""
	if len(args) >= 1 {
		ifaceName = args[0]
		// Ultra-resilient UX: If the user accidentally passed a full Vane token (like "eno1|>...33"), extract the interface!
		if t, isVane := uip.ExtractToken(ifaceName); isVane {
			ifaceName = t.Interface
		}
	} else {
		ifaceName = getDefaultActiveInterface()
	}
	if ifaceName == "" {
		fmt.Fprintln(os.Stderr, "[vane] Error: No active network interface with a valid IPv4 address found to scan.")
		os.Exit(1)
	}

	// Resolve alias/index to real name if passed
	state, err := netstate.GetInterfaceState(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}

	err = scan.PerformScan(state.InterfaceName)
	if err != nil {
		if errors.Is(err, scan.ErrReexec) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
