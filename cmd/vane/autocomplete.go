package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"vane/pkg/netstate"
	"vane/pkg/uip"
)

// handleAutocomplete processes autocomplete inputs from the shell script
func handleAutocomplete(words []string) {
	if len(words) <= 1 {
		// Suggest main commands
		fmt.Println("scan trace sniff send recv doc man help")
		return
	}

	subCmd := words[1]

	// If we are at the second word (e.g. vane p[Tab])
	if len(words) == 2 {
		fmt.Println("scan trace sniff send recv doc man help")
		return
	}

	// Dynamic suggestions for commands that take an interface or target
	if subCmd == "ping" || subCmd == "ssh" || subCmd == "scp" || subCmd == "curl" || subCmd == "scan" || subCmd == "trace" || subCmd == "sniff" || subCmd == "check" {
		// Only suggest on the first argument after the command (e.g., vane ping [Tab])
		if len(words) == 3 {
			var suggestions []string

			// Gather interfaces and active indices
			ifaces, err := net.Interfaces()
			if err == nil {
				activeCount := 0
				for _, iface := range ifaces {
					isUp := (iface.Flags & net.FlagUp) != 0
					isLoopback := (iface.Flags & net.FlagLoopback) != 0

					if isLoopback {
						suggestions = append(suggestions, iface.Name)
						suggestions = append(suggestions, "0")
						suggestions = append(suggestions, "\"0|:...1\"")
					} else if isUp {
						activeCount++
						suggestions = append(suggestions, iface.Name)
						suggestions = append(suggestions, strconv.Itoa(activeCount))

						// Add a helpful syntax suggestion based on active IP (v4 or gateway)
						state, err := netstate.GetInterfaceState(iface.Name)
						if err == nil {
							if state.IPv4Local != nil {
								lastOctet := "53"
								parts := strings.Split(state.IPv4Local.String(), ".")
								if len(parts) == 4 {
									lastOctet = parts[3]
								}
								suggestions = append(suggestions, fmt.Sprintf("\"%d|>...%s\"", activeCount, lastOctet))
								suggestions = append(suggestions, fmt.Sprintf("\"%s|>...%s\"", iface.Name, lastOctet))
							}
							gwIP, err := uip.GetDefaultGateway(iface.Name)
							if err == nil && gwIP != "" {
								suggestions = append(suggestions, fmt.Sprintf("\"%d|>...gw\"", activeCount))
								suggestions = append(suggestions, fmt.Sprintf("\"%s|>...gw\"", iface.Name))
							}
						}
					}
				}
			}

			fmt.Println(strings.Join(suggestions, " "))
			return
		}
	}
}

func printAutocompleteHelp() {
	if getSystemLanguage() == "de" {
		fmt.Println("vane autocomplete ─ Intelligente shell-spezifische Autovervollständigung")
		fmt.Println("\nNutzung:")
		fmt.Println("  vane autocomplete script         Gibt das universelle Shell-Vervollständigungsskript aus.")
		fmt.Println("\nInstallation:")
		fmt.Println("  Füge die folgende Zeile am Ende deiner ~/.bashrc (oder ~/.zshrc) hinzu:")
		fmt.Println("  source <(vane autocomplete script)")
		fmt.Println("\nFunktionsweise:")
		fmt.Println("  Nach der Installation vervollständigt Vane automatisch:")
		fmt.Println("  - Befehle (ping, scan, trace, sniff, etc.)")
		fmt.Println("  - Schnittstellennamen (eno1, lo)")
		fmt.Println("  - Numerische Schnittstellen-Indizes ([0], [1])")
		fmt.Println("  - Vane-Syntaxvorlagen (z.B. \"1|>...gw\")")
	} else {
		fmt.Println("vane autocomplete ─ Intelligent Shell Autocompletion Engine")
		fmt.Println("\nUsage:")
		fmt.Println("  vane autocomplete script         Outputs the universal shell completion script.")
		fmt.Println("\nInstallation:")
		fmt.Println("  Add the following line to the end of your ~/.bashrc (or ~/.zshrc):")
		fmt.Println("  source <(vane autocomplete script)")
		fmt.Println("\nFeatures:")
		fmt.Println("  Once installed, Vane will automatically complete:")
		fmt.Println("  - Commands (ping, scan, trace, sniff, etc.)")
		fmt.Println("  - Interface names (eno1, lo)")
		fmt.Println("  - Numeric interface indices ([0], [1])")
		fmt.Println("  - Vane syntax templates (e.g. \"1|>...gw\")")
	}
}

func printCompletionScript() {
	script := `# Bash & Zsh completion for vane
_vane_completions() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Call vane to get dynamic completions
    local completions
    completions=$(vane autocomplete --complete "${COMP_WORDS[@]:0:COMP_CWORD+1}")

    COMPREPLY=( $(compgen -W "$completions" -- "$cur") )
    return 0
}

# Register completion
if [ -n "$BASH_VERSION" ]; then
    complete -F _vane_completions vane
elif [ -n "$ZSH_VERSION" ]; then
    autoload -U +X bashcompinit && bashcompinit
    complete -F _vane_completions vane
fi
`
	fmt.Print(script)
}
