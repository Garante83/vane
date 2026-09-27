package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"vane/pkg/netstate"
	"vane/pkg/uip"
	"vane/pkg/util"
)

// runDiscoverSubcommand implements the 'vane discover [interface] [flags]'
// argument extraction (including sudo self-re-execution for active modes)
// and hands over to handleDiscoverSubcommand.
func runDiscoverSubcommand(args []string) {
	ifaceName := ""
	persistent := false
	sweepFlag := false
	clearFlag := false
	editFlag := false
	exportFlag := false
	importCode := ""

	// Parse options
	targetSpec := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--persistent" || arg == "-p" {
			persistent = true
		} else if arg == "--sweep" || arg == "-w" {
			sweepFlag = true
		} else if arg == "--specific" || arg == "-s" {
			if i+1 < len(args) {
				targetSpec = args[i+1]
				i++
			}
		} else if arg == "--clear" || arg == "-c" {
			clearFlag = true
		} else if arg == "--edit" || arg == "-e" {
			editFlag = true
		} else if arg == "--export" || arg == "-x" {
			exportFlag = true
		} else if arg == "--import" || arg == "-i" {
			if i+1 < len(args) {
				importCode = args[i+1]
				i++
			}
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
			if util.GetSystemLanguage() == "de" {
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
			if util.GetSystemLanguage() == "de" {
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
		// List available interfaces to help the user
		ifaces, _ := net.Interfaces()
		if util.GetSystemLanguage() == "de" {
			fmt.Fprintf(os.Stderr, "[vane] Fehler: Keine gültige Netzwerk-Schnittstelle gefunden.\n")
			fmt.Fprintf(os.Stderr, "  Verfügbare Schnittstellen:\n")
		} else {
			fmt.Fprintf(os.Stderr, "[vane] Error: No valid network interface found.\n")
			fmt.Fprintf(os.Stderr, "  Available interfaces:\n")
		}
		for _, iface := range ifaces {
			fmt.Fprintf(os.Stderr, "    - %s\n", iface.Name)
		}
		os.Exit(1)
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

	// Handle editor, clear, export and import actions immediately (independent of active interface state)
	if clearFlag || editFlag || exportFlag || importCode != "" {
		err := handleDiscoverSubcommand(ifaceName, persistent, sweepFlag, clearFlag, editFlag, targetIP, targetMAC, exportFlag, importCode)
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

	err = handleDiscoverSubcommand(ifaceName, persistent, sweepFlag, clearFlag, editFlag, targetIP, targetMAC, exportFlag, importCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vane] Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
