//go:build !linux && !windows
package sniff

import "fmt"

// PerformSniff is the fallback compilation stub for unsupported systems
func PerformSniff(ifaceName string) error {
	return fmt.Errorf("sniffing is currently only supported on Linux (packet sniffing) and Windows (active connection monitor)")
}
