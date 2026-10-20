package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type socketObserverContextKey struct{}

type socketObservationLog struct {
	mu     sync.Mutex
	events []SocketEvent
	badCtx bool
}

func (l *socketObservationLog) observe(ctx context.Context, event SocketEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.badCtx = l.badCtx || ctx.Value(socketObserverContextKey{}) != l
	l.events = append(l.events, event)
}

func (l *socketObservationLog) snapshot(t *testing.T) []SocketEvent {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.badCtx {
		t.Error("observer lost the caller context")
	}
	return append([]SocketEvent(nil), l.events...)
}

// The peer checks the actual wire question independently of the resolver and
// observer. In particular a DNS/TCP length prefix must never appear on UDP.
func socketDNSResponse(query []byte, truncated bool) ([]byte, error) {
	if len(query) < 17 || query[2]&0xf8 != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("invalid DNS query header or UDP framing")
	}
	end := 12
	var labels []string
	for end < len(query) && query[end] != 0 {
		size := int(query[end])
		if size > 63 || end+1+size >= len(query) {
			return nil, errors.New("invalid DNS question label")
		}
		labels = append(labels, string(query[end+1:end+1+size]))
		end += 1 + size
	}
	if end+5 > len(query) || strings.Join(labels, ".") != "observer.example.invalid" || binary.BigEndian.Uint16(query[end+3:end+5]) != 1 {
		return nil, errors.New("unexpected DNS question")
	}
	qtype := binary.BigEndian.Uint16(query[end+1 : end+3])
	if qtype != 1 && qtype != 28 {
		return nil, errors.New("unexpected DNS question type")
	}
	response := append([]byte(nil), query[:end+5]...)
	response[2], response[3] = 0x81, 0x80
	clear(response[6:12])
	if truncated {
		response[2] |= 2
	} else if qtype == 1 {
		response[7] = 1
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
	}
	return response, nil
}

func newSocketDNSPeer(t *testing.T, host string, fallback bool) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	udp.SetDeadline(deadline)
	tcp.(*net.TCPListener).SetDeadline(deadline)
	var udpQueries, tcpQueries atomic.Int32
	peerErrors := make(chan error, 32)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 16 {
			buf := make([]byte, 4096)
			n, peer, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			response, err := socketDNSResponse(buf[:n], fallback)
			if err != nil {
				peerErrors <- err
				return
			}
			udpQueries.Add(1)
			if _, err := udp.WriteToUDP(response, peer); err != nil {
				peerErrors <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 16 {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(deadline)
			func() {
				defer conn.Close()
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					peerErrors <- err
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					peerErrors <- err
					return
				}
				response, err := socketDNSResponse(query, false)
				if err != nil {
					peerErrors <- err
					return
				}
				tcpQueries.Add(1)
				binary.BigEndian.PutUint16(length[:], uint16(len(response)))
				if _, err := conn.Write(append(length[:], response...)); err != nil {
					peerErrors <- err
				}
			}()
		}
	}()
	t.Cleanup(func() {
		udp.Close()
		tcp.Close()
		wg.Wait()
		close(peerErrors)
		for err := range peerErrors {
			t.Error(err)
		}
	})
	return udp.LocalAddr().String(), &udpQueries, &tcpQueries
}

func TestSocketObserverRealDNSPreservesUDPAndTCPFraming(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, fallback := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tcp=%t", host, fallback), func(t *testing.T) {
				dns, udpQueries, tcpQueries := newSocketDNSPeer(t, host, fallback)
				var log socketObservationLog
				ctx, cancel := context.WithTimeout(context.WithValue(t.Context(), socketObserverContextKey{}, &log), 2*time.Second)
				defer cancel()
				selector := func(remote net.IP) (net.IP, error) {
					if remote.To4() != nil {
						return net.ParseIP("127.0.0.2"), nil
					}
					return net.ParseIP("::1"), nil
				}
				// Nil and enabled observation must resolve and select the same peer.
				for _, observer := range []SocketObserver{nil, log.observe} {
					socket, err := NewSocketManagerWithObserver(ctx, "127.0.0.2:0", "observer.example.invalid:500", dns, nil, selector, observer)
					if err != nil {
						t.Fatal(err)
					}
					if !socket.RemoteIP().Equal(net.ParseIP("127.0.0.1")) || !socket.LocalIP().Equal(net.ParseIP("127.0.0.2")) {
						t.Error("observation changed resolution or source selection")
					}
					socket.Stop()
				}
				if udpQueries.Load() < 4 || (fallback && tcpQueries.Load() < 4) || (!fallback && tcpQueries.Load() != 0) {
					t.Fatalf("unexpected real DNS exchanges: UDP=%d TCP=%d", udpQueries.Load(), tcpQueries.Load())
				}
				counts := make(map[SocketPhase]int)
				for _, event := range log.snapshot(t) {
					if event.Role != SocketRoleDNS {
						continue
					}
					if event.Remote != netip.MustParseAddrPort(dns) {
						t.Errorf("observed resolver placeholder instead of actual DNS peer: %+v", event)
					}
					if event.Result == SocketResultStarted {
						if event.Source.IsValid() {
							t.Error("dial start guessed a local source before bind")
						}
						continue
					}
					wantSource := netip.MustParseAddr("127.0.0.2")
					if host == "::1" {
						wantSource = netip.IPv6Loopback()
					}
					if event.Result != SocketResultSuccess || event.Source != wantSource || event.Cause != SocketCauseNone {
						t.Errorf("incorrect actual DNS transport metadata: %+v", event)
					}
					if event.Phase != SocketPhaseDial && event.Bytes <= 0 {
						t.Error("successful I/O did not report actual positive bytes")
					}
					counts[event.Phase]++
				}
				for _, phase := range []SocketPhase{SocketPhaseDial, SocketPhaseWrite, SocketPhaseRead} {
					if counts[phase] < 2 {
						t.Errorf("missing actual DNS phase %d: %v", phase, counts)
					}
				}
			})
		}
	}
}

func TestSocketObserverDNSRefusalTimeoutAndCancellationNeverReportResponse(t *testing.T) {
	for _, mode := range []string{"refused", "timeout", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			dns := peer.LocalAddr().String()
			defer peer.Close()
			if mode == "refused" {
				peer.Close()
			}
			var log socketObservationLog
			ctx, cancel := context.WithTimeout(context.WithValue(t.Context(), socketObserverContextKey{}, &log), 150*time.Millisecond)
			defer cancel()
			if mode == "canceled" {
				// Cancel only after a real query, not before the operation starts.
				peer.SetReadDeadline(time.Now().Add(time.Second))
				done := make(chan struct{})
				go func() {
					defer close(done)
					var query [4096]byte
					if _, _, err := peer.ReadFromUDP(query[:]); err == nil {
						cancel()
					}
				}()
				t.Cleanup(func() { peer.Close(); <-done })
			}
			terminal := make(chan SocketEvent, 16)
			observer := func(ctx context.Context, event SocketEvent) {
				log.observe(ctx, event)
				if event.Role == SocketRoleDNS && event.Result == SocketResultFailure {
					terminal <- event
				}
			}
			socket, err := NewSocketManagerWithObserver(ctx, "127.0.0.1:0", "observer.example.invalid:500", dns, nil, nil, observer)
			if socket != nil || err == nil {
				t.Fatal("DNS transport failure created an outer socket")
			}
			select {
			case event := <-terminal:
				want := SocketCauseTimeout
				if mode == "refused" {
					want = SocketCauseRefused
				}
				// Resolver detaches the lookup deadline, and can return before its
				// pending Read's native deadline. Do not change that policy to make
				// this test faster or infer cancel from parent.Err().
				if event.Cause != want && !(mode == "canceled" && event.Cause == SocketCauseCanceled) {
					t.Errorf("incorrect typed transport failure: %+v", event)
				}
			case <-time.After(7 * time.Second):
				t.Fatal("missing actual DNS transport failure")
			}
			for _, event := range log.snapshot(t) {
				if event.Role == SocketRoleOuter || (event.Phase == SocketPhaseRead && event.Result == SocketResultSuccess) {
					t.Errorf("failure fabricated response or outer progress: %+v", event)
				}
			}
		})
	}
}

func TestSocketObserverPreservesErrorsAndDoesNotGuessSource(t *testing.T) {
	marker := errors.New("private error detail must never enter an event")
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EADDRINUSE, syscall.EADDRNOTAVAIL} {
		var log socketObservationLog
		ctx := context.WithValue(t.Context(), socketObserverContextKey{}, &log)
		var baseline *net.DNSError
		for _, observer := range []SocketObserver{nil, log.observe} {
			_, err := NewSocketManagerWithObserver(ctx, "127.0.0.1:0", "observer.example.invalid:500", "127.0.0.1:53", func(string, string, syscall.RawConn) error {
				return errors.Join(marker, errno)
			}, nil, observer)
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) {
				t.Fatal("Resolver did not preserve its original DNS error type")
			}
			if observer == nil {
				baseline = dnsErr
			} else if dnsErr.Err != baseline.Err || dnsErr.Name != baseline.Name || dnsErr.IsTimeout != baseline.IsTimeout || dnsErr.IsTemporary != baseline.IsTemporary || dnsErr.IsNotFound != baseline.IsNotFound || errors.Is(dnsErr, marker) != errors.Is(baseline, marker) || errors.Is(dnsErr, errno) != errors.Is(baseline, errno) {
				t.Fatal("observation altered the original Resolver error or unwrap behavior")
			}
		}
		causes := map[syscall.Errno]SocketCause{syscall.EPERM: SocketCausePermission, syscall.ECONNREFUSED: SocketCauseRefused, syscall.ENETUNREACH: SocketCauseUnreachable, syscall.EADDRINUSE: SocketCauseAddressInUse, syscall.EADDRNOTAVAIL: SocketCauseAddressUnavailable}
		failures := 0
		for _, event := range log.snapshot(t) {
			if strings.Contains(fmt.Sprint(event), marker.Error()) || event.Source.IsValid() {
				t.Fatal("event leaked an error or guessed an unbound source")
			}
			if event.Result == SocketResultFailure {
				failures++
				if event.Cause != causes[errno] || event.Remote != netip.MustParseAddrPort("127.0.0.1:53") {
					t.Errorf("incorrect dial failure metadata: %+v", event)
				}
			}
		}
		if failures == 0 {
			t.Error("missing actual failed dial observation")
		}
	}
}

func TestSocketObserverUnknownEndpointRemainsUnknown(t *testing.T) {
	var log socketObservationLog
	ctx := context.WithValue(t.Context(), socketObserverContextKey{}, &log)
	_, err := NewSocketManagerWithObserver(ctx, "127.0.0.1:0", "observer.example.invalid:500", "missing-port", nil, nil, log.observe)
	if err == nil {
		t.Fatal("malformed DNS endpoint unexpectedly succeeded")
	}
	events := log.snapshot(t)
	if len(events) == 0 {
		t.Fatal("missing attempted DNS dial observations")
	}
	for _, event := range events {
		if event.Remote.IsValid() || event.Source.IsValid() {
			t.Error("unknown endpoint was filled from a resolver placeholder or guessed source")
		}
	}
}

func TestSocketObserverRealOuterUDPDoesNotChangePackets(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	var log socketObservationLog
	ctx := context.WithValue(t.Context(), socketObserverContextKey{}, &log)
	socket, err := NewSocketManagerWithObserver(ctx, "127.0.0.1:0", peer.LocalAddr().String(), "", nil, nil, log.observe)
	if err != nil {
		t.Fatal(err)
	}
	socket.Start()
	defer socket.Stop()
	for index, send := range []func([]byte) error{socket.SendIKE, socket.SendESP, func([]byte) error { return socket.SendNATKeepalive() }} {
		packet := []byte{1, 2, 3, 4, 5}
		if index == 2 {
			packet = []byte{0xff}
		}
		if err := send(packet); err != nil {
			t.Fatal(err)
		}
		var buf [64]byte
		n, client, err := peer.ReadFromUDP(buf[:])
		if err != nil || !bytes.Equal(buf[:n], packet) {
			t.Fatal("observation changed an outer UDP packet")
		}
		if index == 0 {
			if _, err := peer.WriteToUDP(packet, client); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-socket.ESPChan:
				if !bytes.Equal(got, packet) {
					t.Error("observation changed received bytes")
				}
			case <-time.After(time.Second):
				t.Fatal("outer UDP read did not complete")
			}
		}
	}
	socket.Conn.Close()
	if err := socket.SendIKE([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("observation changed closed socket error")
	}
	writes, reads, failures := 0, 0, 0
	for _, event := range log.snapshot(t) {
		if event.Role != SocketRoleOuter {
			t.Error("literal ePDG unexpectedly caused DNS observation")
		}
		if event.Phase == SocketPhaseWrite && event.Result == SocketResultSuccess {
			writes++
		}
		if event.Phase == SocketPhaseRead && event.Result == SocketResultSuccess {
			reads++
		}
		if event.Result == SocketResultFailure {
			failures++
			if event.Cause != SocketCauseClosed {
				t.Error("incorrect outer failure category")
			}
			if event.Phase == SocketPhaseRead && event.Remote.IsValid() {
				t.Error("failed read guessed a peer with no received packet")
			}
		}
	}
	if writes != 3 || reads != 1 || failures == 0 {
		t.Fatalf("missing actual outer I/O: write=%d read=%d failures=%d", writes, reads, failures)
	}
}
