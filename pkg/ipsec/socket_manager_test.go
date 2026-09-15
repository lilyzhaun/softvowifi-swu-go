package ipsec

import (
	"net"
	"testing"
)

func Test_SocketManager_AssignsEphemeralLocalPort_whenLocalPortIsZero(t *testing.T) {
	// Given: a socket manager bound to an ephemeral local port
	sm, err := NewSocketManager("127.0.0.1:0", "127.0.0.1:500", "")
	if err != nil {
		t.Fatalf("NewSocketManager failed: %v", err)
	}
	defer sm.Conn.Close()

	// When: the assigned local port is queried
	port := sm.LocalPort()
	addr := sm.LocalAddr

	// Then: the kernel-assigned port is non-zero and exposed consistently
	if port == 0 {
		t.Fatalf("expected non-zero ephemeral local port, got 0")
	}
	if addr == nil {
		t.Fatalf("expected LocalAddr to be set")
	}
	if int(port) != addr.Port {
		t.Fatalf("LocalPort() = %d, LocalAddr.Port = %d; want them equal", port, addr.Port)
	}
	if !addr.IP.Equal(sm.Conn.LocalAddr().(*net.UDPAddr).IP) {
		t.Fatalf("LocalAddr.IP = %v, conn local IP = %v; want them equal", addr.IP, sm.Conn.LocalAddr().(*net.UDPAddr).IP)
	}
}

func Test_SocketManager_SetRemotePort_ChangesOnlyRemotePort_whenCalled(t *testing.T) {
	// Given: a socket manager with a bound local socket and remote port 500
	sm, err := NewSocketManager("127.0.0.1:0", "127.0.0.1:500", "")
	if err != nil {
		t.Fatalf("NewSocketManager failed: %v", err)
	}
	defer sm.Conn.Close()

	connBefore := sm.Conn
	localPortBefore := sm.LocalPort()
	localAddrBefore := sm.LocalAddr

	// When: the remote port is changed to 4500
	sm.SetRemotePort(4500)

	// Then: only the remote port changed; socket and local address are preserved
	if sm.RemotePort() != 4500 {
		t.Fatalf("RemotePort() = %d, want 4500", sm.RemotePort())
	}
	if sm.Conn != connBefore {
		t.Fatalf("Conn pointer changed after SetRemotePort")
	}
	if sm.LocalPort() != localPortBefore {
		t.Fatalf("LocalPort() = %d, want %d (unchanged)", sm.LocalPort(), localPortBefore)
	}
	if sm.LocalAddr != localAddrBefore {
		t.Fatalf("LocalAddr changed after SetRemotePort")
	}
}
