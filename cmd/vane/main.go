package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"vane/pkg/doc"
	"vane/pkg/netstate"
	"vane/pkg/peeker"
	"vane/pkg/scan"
	"vane/pkg/sniff"
	"vane/pkg/trace"
	"vane/pkg/transfer"
	"vane/pkg/uip"
	"vane/pkg/vssd"
)

var Version = "v1.0.0"

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
	if getSystemLanguage() == "de" {
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
		doc.ShowManual(getSystemLanguage())
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
		ifaceName := ""
		if len(os.Args) >= 3 {
			ifaceName = os.Args[2]
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
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.55 Subcommand: Explain (vane explain <notation>)
	if os.Args[1] == "explain" {
		if len(os.Args) < 3 {
			if getSystemLanguage() == "de" {
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
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "[vane] Error: Target host expected for trace (e.g. vane trace google.com)")
			os.Exit(1)
		}
		target := os.Args[2]

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

	// 2.7 Subcommand: Send (vane send <datei> --code <code>)
	if os.Args[1] == "send" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "[vane] Error: File path expected to send (e.g. vane send backup.tar.gz)")
			os.Exit(1)
		}
		filePath := os.Args[2]

		code := ""
		for i := 3; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--code" || os.Args[i] == "-c" {
				code = os.Args[i+1]
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

	// 2.8 Subcommand: Recv (vane recv [--port <port>])
	if os.Args[1] == "recv" {
		port := "8484"
		for i := 2; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--port" || os.Args[i] == "-p" {
				port = os.Args[i+1]
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

	// 2.9 Subcommand: Sniff (vane sniff [interface])
	if os.Args[1] == "sniff" {
		ifaceName := ""
		if len(os.Args) >= 3 {
			ifaceName = os.Args[2]
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
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2.95 Subcommand: Discover (vane discover [interface] [--persistent] [--sweep] [--specific IP] [--clear] [--edit])
	if os.Args[1] == "discover" {
		ifaceName := ""
		persistent := false
		sweepFlag := false
		clearFlag := false
		editFlag := false

		// Parse options
		targetSpec := ""
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			if arg == "--persistent" || arg == "-p" {
				persistent = true
			} else if arg == "--sweep" || arg == "-w" {
				sweepFlag = true
			} else if arg == "--specific" || arg == "-s" {
				if i+1 < len(os.Args) {
					targetSpec = os.Args[i+1]
					i++
				}
			} else if arg == "--clear" || arg == "-c" {
				clearFlag = true
			} else if arg == "--edit" || arg == "-e" {
				editFlag = true
			} else if !strings.HasPrefix(arg, "-") {
				if strings.Contains(arg, "|>") || strings.Contains(arg, "...") || net.ParseIP(arg) != nil {
					targetSpec = arg
				} else if ifaceName == "" {
					ifaceName = arg
				} else {
					targetSpec = arg
				}
			}
		}

		if targetSpec != "" {
			_, isVane := uip.ExtractToken(targetSpec)
			isIP := net.ParseIP(targetSpec) != nil
			if !isVane && !isIP {
				if getSystemLanguage() == "de" {
					fmt.Fprintf(os.Stderr, "[vane] Fehler: Ungültiges Scan-Ziel '%s'. Das Ziel muss eine valide IP-Adresse oder die strikte Vane-Notation sein (z.B. '1|>...pve' oder 'eno1|>...pve').\n", targetSpec)
				} else {
					fmt.Fprintf(os.Stderr, "[vane] Error: Invalid scan target '%s'. Target must be a valid IP address or a strict Vane notation (e.g. '1|>...pve' or 'eno1|>...pve').\n", targetSpec)
				}
				os.Exit(1)
			}

			if t, isVane := uip.ExtractToken(targetSpec); isVane {
				if ifaceName == "" {
					ifaceName = t.Interface
				}
			}
		}

		// Enforce root privileges on non-Windows systems using secure sudo self-re-execution for active sweeps or interactive editor
		if (sweepFlag || editFlag) && targetSpec == "" && runtime.GOOS != "windows" && os.Geteuid() != 0 {
			// Check if sudo requires a password (non-interactive check)
			needsPassword := true
			checkCmd := exec.Command("sudo", "-n", "true")
			if errCheck := checkCmd.Run(); errCheck == nil {
				needsPassword = false
			}

			if needsPassword {
				if getSystemLanguage() == "de" {
					if editFlag {
						fmt.Println("  \x1b[1;33m[!] root-Rechte für den Service-Editor benötigt. Starte neu mit 'sudo'...\x1b[0m")
					} else {
						fmt.Println("  \x1b[1;33m[!] root-Rechte für Nachbarschafts-Sweep benötigt. Starte neu mit 'sudo'...\x1b[0m")
					}
				} else {
					if editFlag {
						fmt.Println("  \x1b[1;33m[!] root privileges required for service editor. Relaunching with 'sudo'...\x1b[0m")
					} else {
						fmt.Println("  \x1b[1;33m[!] root privileges required for neighborhood sweep. Relaunching with 'sudo'...\x1b[0m")
					}
				}
			}

			cmd := exec.Command("sudo", os.Args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			errRun := cmd.Run()
			if errRun != nil {
				fmt.Fprintf(os.Stderr, "sudo re-execution failed: %v\n", errRun)
				os.Exit(1)
			}
			os.Exit(0)
		}

		if ifaceName == "" {
			ifaceName = getDefaultActiveInterface()
		}
		if ifaceName == "" {
			ifaceName = "eno1" // absolute fallback
		}

		// Resolve alias/index to real name if passed (e.g. "1" -> "eno1")
		// Clean full token notation if passed
		if t, isVane := uip.ExtractToken(ifaceName); isVane {
			ifaceName = t.Interface
		}

		// Resolve interface state once up front to support aliases/indices everywhere
		state, err := netstate.GetInterfaceState(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		ifaceName = state.InterfaceName

		var targetIP, targetMAC string
		if targetSpec != "" {
			if net.ParseIP(targetSpec) != nil {
				targetIP = targetSpec
			} else if t, isVane := uip.ExtractToken(targetSpec); isVane {
				tState, errT := netstate.GetInterfaceState(t.Interface)
				if errT == nil {
					resolved, errResolve := uip.ResolveTokenIP(t, tState)
					if errResolve == nil {
						targetIP = resolved
					}
				}
			}
		}

		// Handle editor and clear actions immediately (independent of active interface state)
		if clearFlag || editFlag {
			err := handleDiscoverSubcommand(ifaceName, persistent, sweepFlag, clearFlag, editFlag, targetIP, targetMAC)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}

		if ifaceName == "" && runtime.GOOS == "linux" {
			fmt.Fprintln(os.Stderr, "[vane] Error: No active network interface with a valid IPv4 address found for discovery.")
			os.Exit(1)
		}

		err = handleDiscoverSubcommand(ifaceName, persistent, sweepFlag, clearFlag, editFlag, targetIP, targetMAC)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	nativeCmd := os.Args[1]

	// 3. Scan arguments to find the first Vane-syntax token
	var targetToken *uip.Token
	var tokenArgIndex = -1

	for i := 2; i < len(os.Args); i++ {
		t, isVane := uip.ExtractToken(os.Args[i])
		if isVane {
			targetToken = t
			tokenArgIndex = i
			break
		}
	}

	// If no Vane notation is found, transparently pass through to execute natively
	if targetToken == nil {
		executeNative(nativeCmd, os.Args[2:])
		return
	}

	// 4. Query local interface configuration state via netstate package
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

	// 5. Pre-flight Port-Peeking (Fast TCP reachability check)
	port := targetToken.Port
	if port == "" {
		port = extractPortFromFlags(os.Args[2:])
	}

	if port != "" {
		if !peeker.CheckPort(targetIP, port) {
			fmt.Fprintf(os.Stderr, msg.PreFlightFail, port, targetIP)
			os.Exit(1)
		}
	}

	// 6. Rewrite CLI arguments dynamically
	var finalArgs []string

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
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
		if nativeCmd == "ssh" {
			finalArgs = append(finalArgs, "-p", targetToken.Port)
		} else if nativeCmd == "scp" {
			finalArgs = append(finalArgs, "-P", targetToken.Port)
		}
	}

	// Native system handoff: execution is passed directly to the kernel
	executeNative(nativeCmd, finalArgs)
}
