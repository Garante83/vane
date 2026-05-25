package sniff

import "strings"

// truncateStr prevents terminal text overflows in log detail columns
func truncateStr(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
