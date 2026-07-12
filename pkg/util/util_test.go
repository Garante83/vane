package util

import (
	"os"
	"testing"
)

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncation with ellipsis", "hello world!", 8, "hello..."},
		{"carriage return cleaned", "hello\r\nworld", 15, "hello world"},
		{"newline replaced with space", "line1\nline2", 20, "line1 line2"},
		{"empty string", "", 10, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := TruncateStr(tc.input, tc.maxLen)
			if res != tc.expected {
				t.Errorf("TruncateStr(%q, %d) = %q, expected %q", tc.input, tc.maxLen, res, tc.expected)
			}
		})
	}
}

func TestGetSystemLanguage(t *testing.T) {
	// Save original env
	origLang := os.Getenv("LANG")
	origLCAll := os.Getenv("LC_ALL")
	origLCMessages := os.Getenv("LC_MESSAGES")
	defer func() {
		_ = os.Setenv("LANG", origLang)
		_ = os.Setenv("LC_ALL", origLCAll)
		_ = os.Setenv("LC_MESSAGES", origLCMessages)
	}()

	// Clear all language env vars
	_ = os.Unsetenv("LANG")
	_ = os.Unsetenv("LC_ALL")
	_ = os.Unsetenv("LC_MESSAGES")

	// Test: no env set → default "en"
	lang := GetSystemLanguage()
	if lang != "en" {
		t.Errorf("expected default 'en', got %q", lang)
	}

	// Test: LANG=de_DE.UTF-8 → "de"
	_ = os.Setenv("LANG", "de_DE.UTF-8")
	lang = GetSystemLanguage()
	if lang != "de" {
		t.Errorf("expected 'de' from LANG, got %q", lang)
	}

	// Test: LC_ALL=en_US.UTF-8 → still "de" (LANG was set first and matched)
	_ = os.Setenv("LC_ALL", "en_US.UTF-8")
	lang = GetSystemLanguage()
	if lang != "de" {
		t.Errorf("expected 'de' (LANG checked first), got %q", lang)
	}

	// Test: LC_MESSAGES=de → "de" (LC_MESSAGES checked after LC_ALL)
	_ = os.Unsetenv("LC_ALL")
	_ = os.Setenv("LC_MESSAGES", "de")
	lang = GetSystemLanguage()
	if lang != "de" {
		t.Errorf("expected 'en' from LC_MESSAGES, got %q", lang)
	}
}
