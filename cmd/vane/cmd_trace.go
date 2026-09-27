package main

import (
	"fmt"
	"os"

	"vane/pkg/netstate"
	"vane/pkg/trace"
	"vane/pkg/uip"
)

// runTraceSubcommand implements the 'vane trace <target>' argument extraction,
// resolves Vane tokens to raw targets and starts the latency profiler.
func runTraceSubcommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "[vane] Error: Target host expected for trace (e.g. vane trace google.com)")
		os.Exit(1)
	}
	target := args[0]

	// Ultra-resilient UX: If the user passed a Vane token, resolve it to its raw target IP first!
	if t, isVane := uip.ExtractToken(target); isVane {
		state, err := netstate.GetInterfaceState(t.Interface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		resolved, errResolve := uip.ResolveTokenIP(t, state)
		if errResolve != nil {
			fmt.Fprintln(os.Stderr, errResolve.Error())
			os.Exit(1)
		}
		target = resolved
	}

	err := trace.PerformTrace(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
