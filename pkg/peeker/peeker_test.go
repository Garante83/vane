package peeker

import (
	"net"
	"testing"
)

func TestCheckPort(t *testing.T) {
	// 1. Test reachable port by spawning a dynamic local TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local test listener: %v", err)
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("failed to parse listener port: %v", err)
	}

	// Verify reachable state
	if !CheckPort("127.0.0.1", port) {
		listener.Close()
		t.Errorf("expected port %s on 127.0.0.1 to be reachable, but CheckPort returned false", port)
	}

	// 2. Test unreachable state by closing the listener
	listener.Close()

	if CheckPort("127.0.0.1", port) {
		t.Errorf("expected closed port %s on 127.0.0.1 to be unreachable, but CheckPort returned true", port)
	}
}
