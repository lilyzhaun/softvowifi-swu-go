package ipsec

import (
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestReceiveInvalidDatagramCannotCommitPeer(t *testing.T) {
	s, err := NewSocketManager("127.0.0.1:0", "127.0.0.1:500", "")
	if err != nil {
		t.Fatal(err)
	}
	envelopes := s.IKEEnvelopes()
	s.remoteIPs = append(s.remoteIPs, net.IPv4(127, 0, 0, 2))
	s.wg.Add(1)
	go s.readLoop()
	defer s.Stop()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := peer.WriteToUDP([]byte{0xff}, s.LocalAddr); err != nil {
		t.Fatal(err)
	}
	barrier := (&ikev2.IKEHeader{SPIi: 0x0102030405060708, Version: 0x20,
		ExchangeType: ikev2.INFORMATIONAL, Flags: ikev2.FlagResponse, Length: 28}).Encode()
	if _, err := peer.WriteToUDP(barrier, s.LocalAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case envelope := <-envelopes:
		if envelope.Peer.Port != peer.LocalAddr().(*net.UDPAddr).Port {
			t.Fatal("source not preserved")
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not process datagrams")
	}
	if s.RemotePort() != 500 || len(s.remoteIPs) != 2 || len(s.NetEvents) != 0 {
		t.Fatal("unvalidated datagram changed peer port")
	}
}

func TestReceivePeerCommitRequiresBoundInitialPortOrProtection(t *testing.T) {
	s, err := NewSocketManager("127.0.0.1:0", "127.0.0.1:500", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	foreign := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 4500}
	if s.CommitIKEPeer(foreign, true) == nil {
		t.Fatal("foreign IP accepted")
	}
	bound := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if s.CommitIKEPeer(bound, false) == nil || s.RemotePort() != 500 {
		t.Fatal("unprotected port change accepted")
	}
	if err := s.CommitIKEPeer(bound, true); err != nil {
		t.Fatal(err)
	}
	bound.IP[0] ^= 1
	bound.Port = 1
	if s.RemotePort() != 4500 || !s.RemoteIP().Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("committed endpoint aliased caller memory")
	}
	select {
	case event := <-s.NetEvents:
		if event.Type != EventNATPortChanged || event.OldPort != 500 || event.NewPort != 4500 {
			t.Fatal("wrong authenticated endpoint event")
		}
	default:
		t.Fatal("missing endpoint event")
	}
}
