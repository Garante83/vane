package parser

import (
	"regexp"
	"strings"
)

// Token represents the parsed components of a Vane-syntax network token.
type Token struct {
	FullMatch string // The entire matched Vane expression (e.g. "eno1|>...gw:80")
	Interface string // The target network interface name (e.g. "eno1")
	Direction string // The direction modifier: '>', '<', ':', or '!'
	Dots      int    // The number of dots indicating segment masking depth
	HostPart  string // The dynamic host part (numeric octet, "gw", or "router")
	Port      string // Optional TCP/UDP port suffix (e.g. "80")
}

// vaneRegex defines the structural pattern of the Vane CLI syntax.
// It allows optional spaces before the pipe character for clean visual alignments in tables,
// and supports multi-octet host parts (containing dots) and dynamic gateway keywords.
var vaneRegex = regexp.MustCompile(`([a-zA-Z0-9]+)\s*\|([>:<!])(\.+)([0-9\.]+|gw|router)(?::([0-9]+))?`)

// ParseToken validates and parses a token string (maintained for backwards compatibility).
func ParseToken(input string) (*Token, bool) {
	return ExtractToken(input)
}

// ExtractToken scans the input string and extracts the first valid Vane-syntax token.
func ExtractToken(input string) (*Token, bool) {
	matches := vaneRegex.FindStringSubmatch(input)
	if len(matches) == 0 {
		return nil, false
	}
	return &Token{
		FullMatch: matches[0],
		Interface: strings.TrimSpace(matches[1]),
		Direction: matches[2],
		Dots:      len(matches[3]),
		HostPart:  matches[4],
		Port:      matches[5],
	}, true
}
