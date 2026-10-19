package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestSourceIPRejectsInvalidSelectionAndHonorsCancellation(t *testing.T) {
	for _, ip := range []net.IP{nil, net.IPv4zero, net.IPv6zero, net.ParseIP("::1")} {
		var calls atomic.Int32
		_, err := NewSocketManagerWithSource(t.Context(), "[::1]:0", "127.0.0.1:500", "", func(string, string, syscall.RawConn) error { calls.Add(1); return nil }, func(net.IP) (net.IP, error) { return ip, nil })
		if err == nil || calls.Load() != 0 {
			t.Fatalf("invalid source reached a socket: %v calls=%d", err, calls.Load())
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if socket, err := NewSocketManagerWithSource(ctx, "[::1]:0", "epdg.cancel.invalid:500", "127.0.0.1:1", nil, func(net.IP) (net.IP, error) { return net.ParseIP("127.0.0.2"), nil }); err == nil || socket != nil {
		t.Fatal("cancelled DNS created an outer socket")
	}
}

func TestSourceIPDNSFallbackTCPRemainsBoundAndIndependent(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			network, source := "4", "127.0.0.2"
			if host == "::1" {
				network, source = "6", "::1"
			}
			udp, err := net.ListenUDP("udp"+network, &net.UDPAddr{IP: net.ParseIP(host)})
			if err != nil {
				t.Fatal(err)
			}
			tcp, err := net.Listen("tcp"+network, udp.LocalAddr().String())
			if err != nil {
				udp.Close()
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			udp.SetDeadline(deadline)
			tcp.(*net.TCPListener).SetDeadline(deadline)
			var udpControls, tcpControls, tcpReads atomic.Int32
			udpDone, tcpDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(udpDone)
				for count := 0; count < 8; count++ {
					buf := make([]byte, 512)
					n, peer, err := udp.ReadFromUDP(buf)
					if err != nil {
						return
					}
					if n < 12 {
						return
					}
					buf[2], buf[3] = 0x83, 0x80 // Truncated: real Resolver must dial TCP.
					udp.WriteToUDP(buf[:n], peer)
				}
			}()
			go func() {
				defer close(tcpDone)
				for count := 0; count < 8; count++ {
					conn, err := tcp.Accept()
					if err != nil {
						return
					}
					conn.SetDeadline(deadline)
					func() {
						defer conn.Close()
						if !conn.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(source)) {
							return
						}
						length := make([]byte, 2)
						if _, err := io.ReadFull(conn, length); err != nil {
							return
						}
						buf := make([]byte, binary.BigEndian.Uint16(length))
						if _, err := io.ReadFull(conn, buf); err != nil || len(buf) < 17 {
							return
						}
						tcpReads.Add(1)
						end := 12
						for end < len(buf) && buf[end] != 0 {
							end += 1 + int(buf[end])
						}
						if end+5 > len(buf) {
							return
						}
						qtype := binary.BigEndian.Uint16(buf[end+1 : end+3])
						buf = buf[:end+5]
						buf[2], buf[3] = 0x81, 0x80
						clear(buf[6:12])
						if qtype == 1 {
							buf[7] = 1
							buf = append(buf, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
						}
						binary.BigEndian.PutUint16(length, uint16(len(buf)))
						conn.Write(append(length, buf...))
					}()
				}
			}()
			t.Cleanup(func() { udp.Close(); tcp.Close(); <-udpDone; <-tcpDone })
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			control := func(network, _ string, _ syscall.RawConn) error {
				if strings.HasPrefix(network, "tcp") {
					tcpControls.Add(1)
				} else {
					udpControls.Add(1)
				}
				return nil
			}
			selector := func(remote net.IP) (net.IP, error) {
				if remote.To4() != nil {
					return net.ParseIP("127.0.0.2"), nil
				}
				return net.ParseIP("::1"), nil
			}
			socket, err := NewSocketManagerWithSource(ctx, net.JoinHostPort(source, "0"), "epdg.tcp.invalid:500", udp.LocalAddr().String(), control, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Stop()
			if !socket.LocalAddr.IP.Equal(net.ParseIP("127.0.0.2")) || tcpControls.Load() == 0 || udpControls.Load() < 2 || tcpReads.Load() == 0 {
				t.Fatalf("TCP DNS or outer binding incorrect: local=%v udp=%d tcp=%d read=%d", socket.LocalAddr, udpControls.Load(), tcpControls.Load(), tcpReads.Load())
			}
			marker := errors.New("network disappeared")
			if _, err := NewSocketManagerWithSource(ctx, "127.0.0.2:0", "127.0.0.1:500", "", func(string, string, syscall.RawConn) error { return marker }, selector); !errors.Is(err, marker) {
				t.Fatal("binding failure escaped to another socket/network")
			}
		})
	}
}
