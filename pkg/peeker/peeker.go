// Package peeker performs fast, non-blocking TCP connectivity probing of
// target ports. Vane calls it before handing execution to hanging commands
// (ssh, curl, ...) to abort early when a target is unreachable.
package peeker

import (
	"net"
	"time"
)

// CheckPort performs a fast TCP connectivity check with a 200ms timeout
// to verify if the target port on the given IP address is reachable.
func CheckPort(ip string, port string) bool {
	address := net.JoinHostPort(ip, port)
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
