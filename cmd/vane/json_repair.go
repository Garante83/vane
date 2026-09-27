package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"vane/pkg/netstate"
	"vane/pkg/uip"
)

func tryAutoRepairJSON(data []byte) ([]byte, error) {
	str := string(data)
	str = strings.TrimSpace(str)
	if str == "" {
		return []byte("{}"), nil
	}

	// 0. Collapse consecutive commas and whitespace (e.g. ,,, or , , , -> ,)
	reMultiCommas := regexp.MustCompile(`,[\s,]+`)
	str = reMultiCommas.ReplaceAllString(str, ",")

	// 1. Remove trailing commas before closing braces/brackets (extremely common manual edit error)
	reTrailingComma := regexp.MustCompile(`, \s*([\}\]])|,\s*([\}\]])`)
	str = reTrailingComma.ReplaceAllString(str, "$1$2")

	// 1.5 Strip trailing comma at the very end of the JSON document
	reEndComma := regexp.MustCompile(`,$`)
	str = reEndComma.ReplaceAllString(str, "")

	// 2. Insert missing commas between consecutive JSON objects/entries (e.g. } "key": { ... } without comma)
	reMissingComma := regexp.MustCompile(`\}\s*"\s*`)
	str = reMissingComma.ReplaceAllString(str, `}, "`)

	// 3. Count open vs close braces and brackets and fix unclosed structures at the end
	openBraces := strings.Count(str, "{")
	closeBraces := strings.Count(str, "}")
	openBrackets := strings.Count(str, "[")
	closeBrackets := strings.Count(str, "]")

	if openBrackets > closeBrackets {
		str += strings.Repeat("]", openBrackets-closeBrackets)
	}
	if openBraces > closeBraces {
		str += strings.Repeat("}", openBraces-closeBraces)
	}

	// Try unmarshaling to verify if repaired JSON is correct
	var testSchema map[string]interface{}
	err := json.Unmarshal([]byte(str), &testSchema)
	if err == nil {
		pretty, indentErr := json.MarshalIndent(testSchema, "", "  ")
		if indentErr == nil {
			return pretty, nil
		}
		return []byte(str), nil
	}

	return nil, err
}

func validateAndResolveIPInput(input, ifaceName string) (string, error) {
	input = strings.Trim(strings.TrimSpace(input), "\"'")
	if input == "" {
		return "", fmt.Errorf("IP address cannot be empty")
	}

	// Check if it is a Vane/UIP notation (e.g. ...33 or eno1|>...33)
	if tok, found := uip.ExtractToken(input); found {
		state, err := netstate.GetInterfaceState(ifaceName)
		if err != nil {
			return "", fmt.Errorf("failed to get interface state for '%s': %v", ifaceName, err)
		}
		resolved, err := uip.ResolveTokenIP(tok, state)
		if err != nil {
			return "", fmt.Errorf("failed to resolve Vane notation: %v", err)
		}
		if net.ParseIP(resolved) == nil {
			return "", fmt.Errorf("resolved notation '%s' to invalid IP '%s'", input, resolved)
		}
		return resolved, nil
	}

	// Otherwise, validate as direct raw IP
	if net.ParseIP(input) == nil {
		return "", fmt.Errorf("invalid IPv4 or IPv6 address syntax")
	}
	return input, nil
}

func lookupMACByIP(ifaceName, ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if runtime.GOOS == "windows" {
		// Windows: PowerShell required – Go stdlib has no direct access to adapter MAC-to-IP mappings
		cmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Get-NetNeighbor -InterfaceAlias '%s' -IPAddress '%s' | Select-Object -ExpandProperty LinkLayerAddress", ifaceName, ip))
		out, err := cmd.Output()
		if err == nil {
			mac := strings.TrimSpace(string(out))
			mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
			if mac != "" && len(mac) >= 12 {
				return mac, nil
			}
		}
		return "", fmt.Errorf("not found")
	}

	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		entryIP := fields[0]
		mac := strings.ToLower(fields[3])
		dev := fields[5]

		if dev == ifaceName && entryIP == ip {
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac, nil
			}
		}
	}
	return "", fmt.Errorf("not found")
}
