package util

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// TruncateStr shortens a string to maxLen characters, appending "..." if truncated.
// Also cleans carriage returns and newlines for clean terminal output.
func TruncateStr(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// GetSystemLanguage detects the system language from environment variables.
// Returns "de" for German, "en" for English (default).
func GetSystemLanguage() string {
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
		val := os.Getenv(env)
		if val != "" {
			valLower := strings.ToLower(val)
			if strings.HasPrefix(valLower, "de") {
				return "de"
			}
			if strings.HasPrefix(valLower, "en") {
				return "en"
			}
		}
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "[System.Globalization.CultureInfo]::CurrentCulture.TwoLetterISOLanguageName")
		out, err := cmd.Output()
		if err == nil {
			lang := strings.TrimSpace(strings.ToLower(string(out)))
			if lang == "de" {
				return "de"
			}
		}
	}

	return "en"
}
