package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func TestInitialTimeoutReportsOnlyAnAvailableAlternateFamily(t *testing.T) {
	v4, v6 := net.IPv4(127, 0, 0, 1), net.IPv6loopback
	dual := []net.IP{v4, v6}
	for _, test := range []struct {
		name         string
		policy, want ipsec.AddressFamilyPolicy
		peer         net.IP
		answers      []net.IP
	}{
		{"prefer6", ipsec.AddressFamilyPreferIPv6, ipsec.AddressFamilyIPv4Only, v6, dual},
		{"prefer4", ipsec.AddressFamilyPreferIPv4, ipsec.AddressFamilyIPv6Only, v4, dual},
		{"strict", ipsec.AddressFamilyIPv6Only, "", v6, dual},
		{"default", "", "", v4, dual},
		{"only_preferred_answer", ipsec.AddressFamilyPreferIPv6, "", v6, []net.IP{v6}},
		{"already_used_the_only_answer", ipsec.AddressFamilyPreferIPv6, "", v4, []net.IP{v4}},
		{"no_compatible_source", ipsec.AddressFamilyPreferIPv4, "", v4, dual},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer, cfg, sim := initTimeoutPeer(t, test.peer, test.answers, test.policy)
			if test.name == "no_compatible_source" {
				cfg.SourceIP = func(remote net.IP) (net.IP, error) {
					if remote.To4() == nil {
						return nil, syscall.EADDRNOTAVAIL
					}
					return policyFamilySource(remote)
				}
			}
			wait, _ := startInitTimeoutSession(t, cfg)
			assertInitTimeoutRequest(t, peer.receive(t))
			err := <-wait
			if !errors.Is(err, ErrWindowTimeout) || initialFamilyFromError(err) != test.want || sim.imsiCalls != 0 || sim.akaCalls != 0 {
				t.Fatalf("initial result %v, alternate %q; want %q with no SIM reads", err, initialFamilyFromError(err), test.want)
			}
		})
	}
}

func TestNoInitialFamilyRetryAfterPeerProgressOrLocalFailure(t *testing.T) {
	for _, mode := range []string{"cookie", "notify_hint", "auth", "bind_denied", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			answers := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
			peer, cfg, sim := initTimeoutPeer(t, answers[0], answers, ipsec.AddressFamilyPreferIPv4)
			want := ErrWindowTimeout
			if mode == "bind_denied" {
				cfg.DNSServer, _ = familyDNS(t, "udp6", "::1", answers...)
				cfg.SocketControl = func(network, _ string, _ syscall.RawConn) error {
					if network == "udp4" {
						return syscall.EACCES // DNS stays on IPv6; the outer bind is IPv4.
					}
					return nil
				}
				want = syscall.EACCES
			}
			wait, cancel := startInitTimeoutSession(t, cfg)
			switch mode {
			case "auth":
				peer.negotiate(t)
				peer.decrypt(t, peer.receive(t)) // Valid protected AUTH was actually sent; no reply.
			case "cookie", "notify_hint":
				spi := assertInitTimeoutRequest(t, peer.receive(t))
				if mode == "cookie" {
					peer.send(t, initHintWire(spi, uint16(ikev2.COOKIE), []byte{1, 2, 3, 4}))
					retry, err := ikev2.DecodePacket(peer.receive(t))
					if err != nil || len(retry.Payloads) == 0 {
						t.Fatal("the accepted COOKIE did not produce a valid retry", err)
					}
					notify, ok := retry.Payloads[0].(*ikev2.EncryptedPayloadNotify)
					if !ok || notify.NotifyType != ikev2.COOKIE {
						t.Fatal("the real retry did not carry the peer's COOKIE")
					}
				} else {
					peer.send(t, initHintWire(spi, uint16(ikev2.INVALID_KE_PAYLOAD), []byte{0, 19}))
				}
			case "cancelled":
				assertInitTimeoutRequest(t, peer.receive(t))
				want = context.Canceled
				cancel()
			}
			err := <-wait
			if !errors.Is(err, want) || initialFamilyFromError(err) != "" || sim.akaCalls != 0 {
				t.Fatalf("%s: result %v reported an alternate (%q)", mode, err, initialFamilyFromError(err))
			}
			if mode == "notify_hint" && !strings.Contains(err.Error(), "diagnostic hints") {
				t.Fatal("the original accepted diagnostic hint was not preserved")
			}
		})
	}
}

func TestInitialWindowDistinguishesWriteFailuresFromCleanExhaustion(t *testing.T) {
	for _, failedSend := range []int{0, 1, 2} {
		manager, _ := newIdleWindow(t, 1)
		manager.config.MaxRetries = 1
		sends := 0
		manager.sendFunc = func(_ [][]byte) error {
			sends++
			if sends == failedSend {
				return syscall.ENETUNREACH
			}
			return nil
		}
		request := manager.enqueueRequest(0, ikev2.IKE_SA_INIT, nil, [][]byte{{1}})
		for range 2 {
			request.Deadline = time.Unix(1, 0)
			manager.checkTimeouts()
		}
		requireWindowClosed(t, request.CompletionCh)
		if !request.exhausted || request.sendFailed != (failedSend != 0) || sends != 2 {
			t.Fatal("initial or retransmit write failure was confused with clean exhaustion")
		}
	}
}

func initTimeoutPeer(t *testing.T, remote net.IP, answers []net.IP, family ipsec.AddressFamilyPolicy) (*akaWirePeer, *Config, *diagnosticSIM) {
	t.Helper()
	network := "udp6"
	if remote.To4() != nil {
		network = "udp4"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: remote})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dns, _ := familyDNS(t, "udp4", "127.0.0.1", answers...)
	sim := &diagnosticSIM{}
	lifetime := SALifetimePolicy{SoftLifetime: time.Minute, HardLifetime: 90 * time.Second}
	cfg := &Config{EpDGAddr: "init-family.invalid", EpDGPort: uint16(conn.LocalAddr().(*net.UDPAddr).Port), DNSServer: dns,
		SourceIP: policyFamilySource, RemoteAddressFamily: family, SIM: sim, APN: "ims", MCC: "001", MNC: "01",
		RenewalPolicy: &RenewalPolicy{IKE: lifetime, Child: lifetime, Retransmission: RetryConfig{
			InitialTimeout: 500 * time.Millisecond, BackoffFactor: 1,
		}}}
	return &akaWirePeer{conn: conn}, cfg, sim
}

func startInitTimeoutSession(t *testing.T, cfg *Config) (<-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan error, 1)
	go func() { defer close(done); done <- NewSession(cfg, zap.NewNop()).Connect(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return done, cancel
}

func assertInitTimeoutRequest(t *testing.T, wire []byte) uint64 {
	t.Helper()
	if len(wire) < 28 || wire[18] != 34 || binary.BigEndian.Uint32(wire[20:24]) != 0 {
		t.Fatal("expected a real IKE_SA_INIT request")
	}
	return binary.BigEndian.Uint64(wire[:8])
}

func initialFamilyFromError(err error) ipsec.AddressFamilyPolicy {
	var retry interface {
		FallbackAddressFamily() ipsec.AddressFamilyPolicy
	}
	if errors.As(err, &retry) {
		return retry.FallbackAddressFamily()
	}
	return ""
}
