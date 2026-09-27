package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"vane/pkg/doc"
	"vane/pkg/netstate"
	"vane/pkg/uip"
	"vane/pkg/util"
	"vane/pkg/vssd"
)

var Version = "v1.1.0"

func main() {
	// Register the VSSD semantic resolution hook to resolve dynamic service-oriented tokens.
	// By default (active = false), this runs completely silently via cache or standard mDNS lookup,
	// without creating any files on disk or triggering port sweeps.
	uip.ResolveSemanticHook = func(token *uip.Token, state *netstate.State) (string, bool, error) {
		ip, err := vssd.DiscoverService(state.InterfaceName, token.HostPart, false)
		if err == nil {
			return ip, true, nil
		}
		if uip.IsSemanticToken(token.HostPart) {
			return "", true, err
		}
		return "", false, nil
	}

	// Dynamically detect system language for internationalization.
	// If German is detected, switch to German translations.
	if util.GetSystemLanguage() == "de" {
		msg = de
	}

	// 1. Version check flag (must be checked before other arguments)
	if len(os.Args) == 2 && (os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("vane version %s\n", Version)
		os.Exit(0)
	}

	// 1.1 Matrix Report: If no arguments are passed, print the network interface matrix
	if len(os.Args) == 1 {
		printInterfaceMatrix()
		os.Exit(0)
	}

	// 1.5 Intercept autocomplete requests from the shell or for installation
	if len(os.Args) >= 2 && os.Args[1] == "autocomplete" {
		if len(os.Args) >= 3 && os.Args[2] == "--complete" {
			handleAutocomplete(os.Args[3:])
			os.Exit(0)
		}

		// Print installer instructions and the completion script!
		if len(os.Args) >= 3 && (os.Args[2] == "install" || os.Args[2] == "script") {
			printCompletionScript()
			os.Exit(0)
		}

		printAutocompleteHelp()
		os.Exit(0)
	}

	// Simple list flag: Used by the shell autocomplete script to query interface names
	if len(os.Args) == 2 && os.Args[1] == "--list-interfaces-simple" {
		ifaces, err := net.Interfaces()
		if err == nil {
			var names []string
			for _, iface := range ifaces {
				names = append(names, iface.Name)
			}
			fmt.Println(strings.Join(names, " "))
		}
		os.Exit(0)
	}

	// Help screen
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		fmt.Println(msg.HelpTitle)
		fmt.Println(msg.HelpUsageHeader)
		fmt.Println(msg.HelpExecCommand)
		fmt.Println(msg.HelpConvert)
		fmt.Println(msg.HelpScan)
		fmt.Println(msg.HelpTrace)
		fmt.Println(msg.HelpSend)
		fmt.Println(msg.HelpRecv)
		fmt.Println(msg.HelpSniff)
		fmt.Println(msg.HelpDiscover)
		fmt.Println(msg.HelpExplain)
		fmt.Println(msg.HelpManual)
		fmt.Println(msg.HelpMatrix)
		os.Exit(0)
	}

	// 1.5 Interactive Manual Mode (vane doc / man / --manual / -m)
	if len(os.Args) == 2 && (os.Args[1] == "doc" || os.Args[1] == "man" || os.Args[1] == "-m" || os.Args[1] == "--manual") {
		doc.ShowManual(util.GetSystemLanguage())
		os.Exit(0)
	}

	// 2. Infocenter Mode: Handle bidirectional network token conversion (-c / --convert)
	if os.Args[1] == "-c" || os.Args[1] == "--convert" {
		if len(os.Args) < 4 {
			fmt.Fprint(os.Stderr, msg.ErrorTooFewArgs)
			fmt.Fprint(os.Stderr, msg.UsageConvert)
			os.Exit(1)
		}
		handleConvert(os.Args[2], os.Args[3])
		os.Exit(0)
	}

	// 2.5 Subcommand: Scan (vane scan [interface])
	if os.Args[1] == "scan" {
		runScanSubcommand(os.Args[2:])
	}

	// 2.55 Subcommand: Explain (vane explain <notation>)
	if os.Args[1] == "explain" {
		if len(os.Args) < 3 {
			if util.GetSystemLanguage() == "de" {
				fmt.Fprintln(os.Stderr, "[vane] Fehler: Bitte gib eine Notation an (z. B. vane explain lan.1)")
			} else {
				fmt.Fprintln(os.Stderr, "[vane] Error: Please specify a notation to explain (e.g. vane explain lan.1)")
			}
			os.Exit(1)
		}
		handleExplainSubcommand(os.Args[2])
		os.Exit(0)
	}

	// 2.6 Subcommand: Trace (vane trace <target>)
	if os.Args[1] == "trace" {
		runTraceSubcommand(os.Args[2:])
	}

	// 2.7 Subcommand: Send (vane send <datei> --code <code>)
	if os.Args[1] == "send" {
		runSendSubcommand(os.Args[2:])
	}

	// 2.8 Subcommand: Recv (vane recv [--port <port>])
	if os.Args[1] == "recv" {
		runRecvSubcommand(os.Args[2:])
	}

	// 2.9 Subcommand: Sniff (vane sniff [interface])
	if os.Args[1] == "sniff" {
		runSniffSubcommand(os.Args[2:])
	}

	// 2.95 Subcommand: Discover (vane discover [interface] [--persistent] [--sweep] [--specific IP] [--clear] [--edit] [--export] [--import CODE])
	if os.Args[1] == "discover" {
		runDiscoverSubcommand(os.Args[2:])
	}

	nativeCmd := os.Args[1]

	// Transparent proxy handoff for arbitrary native commands with Vane tokens
	runProxyCommand(nativeCmd, os.Args[2:])
}
