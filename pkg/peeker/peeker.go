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
	conn.Close()
	return true
}
