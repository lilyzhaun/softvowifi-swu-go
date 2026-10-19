package swu

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func setFamilySource(cfg *Config, source func(net.IP) (net.IP, error)) {
	cfg.SourceIP = source
}

func familyDNS(t *testing.T, network, host string, answer net.IP) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for count := 0; count < 16; count++ {
			buf := make([]byte, 512)
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			if n < 17 || (peer.IP.To4() != nil) != (net.ParseIP(host).To4() != nil) {
				return
			}
			end := 12
			for end < n && buf[end] != 0 {
				end += 1 + int(buf[end])
			}
			if end+5 > n {
				return
			}
			qtype := binary.BigEndian.Uint16(buf[end+1 : end+3])
			packet := buf[:end+5]
			packet[2], packet[3] = 0x81, 0x80
			clear(packet[6:12])
			ip, typ := answer.To4(), byte(1)
			if ip == nil {
				ip, typ = answer.To16(), 28
			}
			if qtype == uint16(typ) {
				packet[7] = 1
				packet = append(packet, 0xc0, 0x0c, 0, typ, 0, 1, 0, 0, 0, 30, 0, byte(len(ip)))
				packet = append(packet, ip...)
			}
			if _, err := conn.WriteToUDP(packet, peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().String(), &queries
}

func TestTargetFamilySourceUsesIndependentDNSAndEpdgFamilies(t *testing.T) {
	for _, tc := range []struct{ name, dnsNetwork, dnsIP, peerNetwork, peerIP, primary string }{
		{"IPv4_DNS_despite_IPv6_primary", "udp4", "127.0.0.1", "udp4", "127.0.0.1", "::1"},
		{"IPv6_DNS_returns_IPv4", "udp6", "::1", "udp4", "127.0.0.1", "::1"},
		{"IPv4_DNS_returns_IPv6", "udp4", "127.0.0.1", "udp6", "::1", "127.0.0.2"},
		{"IPv6_DNS_returns_IPv6", "udp6", "::1", "udp6", "::1", "::1"},
		{"IPv4_literal_with_IPv6_primary", "", "", "udp4", "127.0.0.1", "::1"},
		{"IPv6_literal_with_IPv4_primary", "", "", "udp6", "::1", "127.0.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, err := net.ListenUDP(tc.peerNetwork, &net.UDPAddr{IP: net.ParseIP(tc.peerIP)})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			cfg := &Config{EpDGAddr: tc.peerIP, EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port), LocalAddr: tc.primary, SIM: &diagnosticSIM{}}
			var queries *atomic.Int32
			if tc.dnsNetwork != "" {
				cfg.DNSServer, queries = familyDNS(t, tc.dnsNetwork, tc.dnsIP, net.ParseIP(tc.peerIP))
				cfg.EpDGAddr = "epdg.family.invalid"
			}
			setFamilySource(cfg, func(remote net.IP) (net.IP, error) {
				if remote.To4() != nil {
					return net.ParseIP("127.0.0.2"), nil
				}
				return net.ParseIP("::1"), nil
			})
			var controls atomic.Int32
			cfg.SocketControl = func(string, string, syscall.RawConn) error { controls.Add(1); return nil }
			session := NewSession(cfg, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			result := make(chan error, 1)
			go func() { result <- session.Connect(ctx) }()
			t.Cleanup(func() { cancel(); <-result })
			peer.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
			buf := make([]byte, 4096)
			n, source, err := peer.ReadFromUDP(buf)
			if err != nil {
				cancel()
				select {
				case connectErr := <-result:
					result <- connectErr
					t.Fatalf("no actual IKE socket/packet: %v (read=%v)", connectErr, err)
				case <-time.After(time.Second):
					t.Fatal("Connect did not cancel")
				}
			}
			if n < 28 || buf[18] != 34 || !source.IP.Equal(net.ParseIP(map[bool]string{true: "127.0.0.2", false: "::1"}[net.ParseIP(tc.peerIP).To4() != nil])) {
				t.Fatalf("not a correctly bound real IKE_INIT: source=%v bytes=%d", source, n)
			}
			if controls.Load() == 0 || queries != nil && (queries.Load() == 0 || controls.Load() < 2) {
				t.Fatal("DNS or outer socket bypassed network control")
			}
			assertFamilyNATSource(t, buf[:n], source)
		})
	}
}

func assertFamilyNATSource(t *testing.T, packet []byte, source *net.UDPAddr) {
	t.Helper()
	ip := source.IP.To4()
	if ip == nil {
		ip = source.IP.To16()
	}
	hash := sha1.New()
	hash.Write(packet[:16])
	hash.Write(ip)
	port := []byte{byte(source.Port >> 8), byte(source.Port)}
	hash.Write(port)
	next := packet[16]
	for offset := 28; offset+4 <= len(packet); {
		length := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		if length < 4 || offset+length > len(packet) {
			t.Fatal("invalid INIT payload")
		}
		if next == 41 && length >= 8 && binary.BigEndian.Uint16(packet[offset+6:offset+8]) == 16388 {
			if !bytes.Equal(packet[offset+8:offset+length], hash.Sum(nil)) {
				t.Fatal("NAT hash did not use the actual outer source family/address/port")
			}
			return
		}
		next = packet[offset]
		offset += length
	}
	t.Fatal("missing NAT source notify")
}

func TestTargetFamilySourceMissingAddressFailsBeforeSocket(t *testing.T) {
	marker := errors.New("selected network has no compatible source")
	var controls atomic.Int32
	cfg := &Config{EpDGAddr: "127.0.0.1", LocalAddr: "::1", SIM: &diagnosticSIM{}, SocketControl: func(string, string, syscall.RawConn) error { controls.Add(1); return nil }}
	setFamilySource(cfg, func(net.IP) (net.IP, error) { return nil, marker })
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := NewSession(cfg, nil).Connect(ctx); !errors.Is(err, marker) || controls.Load() != 0 {
		t.Fatalf("incompatible source did not fail closed: %v calls=%d", err, controls.Load())
	}
}
