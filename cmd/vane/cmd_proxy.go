package main

import (
	"fmt"
	"os"
	"strings"

	"vane/pkg/netstate"
	"vane/pkg/peeker"
	"vane/pkg/uip"
)

// runProxyCommand implements the transparent proxy pass-through for arbitrary
// native commands with Vane notation tokens (e.g. 'vane ssh user@"eno1|>...33"').
func runProxyCommand(nativeCmd string, args []string) {
	// Scan arguments to find the first Vane-syntax token
	var targetToken *uip.Token
	tokenArgIndex := -1

	for i := 0; i < len(args); i++ {
		t, isVane := uip.ExtractToken(args[i])
		if isVane {
			targetToken = t
			tokenArgIndex = i
			break
		}
	}

	// If no Vane notation is found, transparently pass through to execute natively
	if targetToken == nil {
		executeNative(nativeCmd, args)
		return
	}

	// Query local interface configuration state via netstate package
	state, err := netstate.GetInterfaceState(targetToken.Interface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}

	targetIP, errResolve := uip.ResolveTokenIP(targetToken, state)
	if errResolve != nil {
		fmt.Fprintln(os.Stderr, errResolve.Error())
		os.Exit(1)
	}

	// Pre-flight Port-Peeking (Fast TCP reachability check)
	port := targetToken.Port
	if port == "" {
		port = extractPortFromFlags(args)
	}

	if port != "" {
		if !peeker.CheckPort(targetIP, port) {
			fmt.Fprintf(os.Stderr, msg.PreFlightFail, port, targetIP)
			os.Exit(1)
		}
	}

	// Rewrite CLI arguments dynamically
	var finalArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if i == tokenArgIndex {
			replaced := ""
			isWebCmd := nativeCmd == "curl" || nativeCmd == "wget"

			if targetToken.Port != "" {
				if isWebCmd {
					// Retain inline port inside a web query URL
					replaced = strings.ReplaceAll(arg, targetToken.FullMatch, targetIP+":"+targetToken.Port)
				} else {
					// Strip port from the host part (will be appended separately or dropped)
					replaced = strings.ReplaceAll(arg, targetToken.FullMatch, targetIP)
				}
			} else {
				replaced = strings.ReplaceAll(arg, targetToken.FullMatch, targetIP)
			}
			finalArgs = append(finalArgs, replaced)
		} else {
			finalArgs = append(finalArgs, arg)
		}
	}

	// Automatically append protocol-specific port flags for SSH/SCP
	if targetToken.Port != "" {
		switch nativeCmd {
		case "ssh":
			finalArgs = append(finalArgs, "-p", targetToken.Port)
		case "scp":
			finalArgs = append(finalArgs, "-P", targetToken.Port)
		}
	}

	// Native system handoff: execution is passed directly to the kernel
	executeNative(nativeCmd, finalArgs)
}
