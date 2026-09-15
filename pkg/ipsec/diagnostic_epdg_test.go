package ipsec

import (
	"net"
	"testing"
)

func TestDiagnosticLiteralHasSingleRemoteAcrossPortChange(t *testing.T) {
	socket, err := NewSocketManager("127.0.0.1:0", "192.0.2.1:500", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Stop()
	socket.SetRemotePort(4500)
	if len(socket.remoteIPs) != 1 || !socket.remoteIPs[0].Equal(net.IPv4(192, 0, 2, 1)) || !socket.RemoteIP().Equal(net.IPv4(192, 0, 2, 1)) || socket.RemotePort() != 4500 {
		t.Fatal("literal address gained DNS alternatives or changed during NAT-T switch")
	}
}
