package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func setNetworkSocketControl(t *testing.T, cfg *Config, control func(string, string, syscall.RawConn) error) {
	t.Helper()
	field := reflect.ValueOf(cfg).Elem().FieldByName("SocketControl")
	if !field.IsValid() || !field.CanSet() {
		t.Fatal("normal Config has no outer socket/DNS network-control path")
	}
	field.Set(reflect.ValueOf(control))
}

func TestNetworkSocketControlRejectsBeforeAnyNetworkTraffic(t *testing.T) {
	var calls atomic.Int32
	marker := errors.New("selected network unavailable")
	cfg := &Config{EpDGAddr: "127.0.0.1", EpDGPort: 500, LocalAddr: "127.0.0.2", LocalPort: 4500, SIM: &diagnosticSIM{}}
	setNetworkSocketControl(t, cfg, func(network, address string, raw syscall.RawConn) error { calls.Add(1); return marker })
	s := NewSession(cfg, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	defer s.Shutdown()
	if err := s.Connect(ctx); !errors.Is(err, marker) || calls.Load() != 1 {
		t.Fatal("binding failure did not terminate normal Connect without unbound/ephemeral retry")
	}
}

func TestNetworkSocketControlAlsoBindsTheConfiguredDNS(t *testing.T) {
	dns, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	if err := dns.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for n := 0; n < 8; n++ {
			select {
			case <-stop:
				return
			default:
			}
			buf := make([]byte, 512)
			length, peer, err := dns.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if length < 16 {
				return
			}
			end := 12
			for end < length && buf[end] != 0 {
				end += 1 + int(buf[end])
			}
			if end+5 > length {
				return
			}
			questionType := binary.BigEndian.Uint16(buf[end+1 : end+3])
			packet := buf[:end+5]
			packet[2], packet[3] = 0x81, 0x80
			clear(packet[6:12])
			if questionType == 1 {
				packet[7] = 1
				packet = append(packet, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
			}
			if _, err := dns.WriteToUDP(packet, peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); dns.Close(); <-done })
	var dnsCalls, ikeCalls atomic.Int32
	marker := errors.New("test-only selected-network listen stop")
	cfg := &Config{EpDGAddr: "epdg.bound.invalid", EpDGPort: 500, LocalAddr: "127.0.0.2", DNSServer: dns.LocalAddr().String(), SIM: &diagnosticSIM{}}
	setNetworkSocketControl(t, cfg, func(network, address string, raw syscall.RawConn) error {
		if address == dns.LocalAddr().String() {
			dnsCalls.Add(1)
			return nil
		}
		ikeCalls.Add(1)
		return marker
	})
	s := NewSession(cfg, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	defer s.Shutdown()
	if err := s.Connect(ctx); !errors.Is(err, marker) || dnsCalls.Load() == 0 || ikeCalls.Load() != 1 {
		t.Fatalf("DNS or normal IKE listen bypassed selected network control: err=%v dns_calls=%d ike_calls=%d", err, dnsCalls.Load(), ikeCalls.Load())
	}
}

func TestNetworkSocketControlNeverUsesImplicitSystemDNS(t *testing.T) {
	var calls atomic.Int32
	cfg := &Config{EpDGAddr: "epdg.bound.invalid", LocalAddr: "127.0.0.2", SIM: &diagnosticSIM{}}
	setNetworkSocketControl(t, cfg, func(string, string, syscall.RawConn) error { calls.Add(1); return nil })
	s := NewSession(cfg, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	defer s.Shutdown()
	if err := s.Connect(ctx); err == nil || calls.Load() != 0 {
		t.Fatal("selected network without DNS made an implicit default-network request")
	}
}
