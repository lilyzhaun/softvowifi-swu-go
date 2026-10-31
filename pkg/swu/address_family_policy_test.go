package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func policyFamilySource(remote net.IP) (net.IP, error) {
	if remote.To4() != nil {
		return net.ParseIP("127.0.0.2"), nil
	}
	return net.ParseIP("::1"), nil
}

func TestRemoteAddressFamilyCapturedBySessionAndIndependentOfDNS(t *testing.T) {
	for _, dnsHost := range []string{"127.0.0.1", "::1"} {
		for _, policy := range []ipsec.AddressFamilyPolicy{"", "prefer-ipv4", "prefer-ipv6", "ipv4-only", "ipv6-only"} {
			t.Run(dnsHost+"/"+string(policy), func(t *testing.T) {
				wantIP, network := "127.0.0.1", "udp4"
				if policy == "prefer-ipv6" || policy == "ipv6-only" {
					wantIP, network = "::1", "udp6"
				}
				peer, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(wantIP)})
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				dnsNetwork := "udp4"
				if dnsHost == "::1" {
					dnsNetwork = "udp6"
				}
				dns, queries := familyDNS(t, dnsNetwork, dnsHost, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
				var controls atomic.Int32
				cfg := &Config{EpDGAddr: "epdg.policy.invalid", EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port),
					DNSServer: dns, LocalAddr: "127.0.0.2", SourceIP: policyFamilySource, SIM: &diagnosticSIM{},
					SocketControl:       func(string, string, syscall.RawConn) error { controls.Add(1); return nil },
					RemoteAddressFamily: policy}
				session := NewSession(cfg, zap.NewNop())
				// Policy is captured by NewSession, not reread from editable input.
				cfg.RemoteAddressFamily = "unsupported-after-construction"
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				done := make(chan error, 1)
				go func() { done <- session.Connect(ctx); close(done) }()
				t.Cleanup(func() {
					cancel()
					session.Shutdown()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("family policy session did not retire")
					}
				})
				peer.SetReadDeadline(time.Now().Add(time.Second))
				var wire [4096]byte
				n, source, err := peer.ReadFromUDP(wire[:])
				if err != nil {
					t.Fatal("captured family did not reach the real IKE peer", err)
				}
				if n < 28 || wire[18] != 34 || queries.Load() == 0 || controls.Load() < 2 {
					t.Fatal("family selection skipped real DNS, socket control, or IKE_INIT")
				}
				wantSource, _ := policyFamilySource(net.ParseIP(wantIP))
				if !source.IP.Equal(wantSource) {
					t.Fatal("remote preference changed selected-network source ownership")
				}
				assertFamilyNATSource(t, wire[:n], source)
			})
		}
	}
}

func TestRemoteAddressFamilyRejectsInvalidAndLiteralConflictBeforeDial(t *testing.T) {
	for _, test := range []struct {
		policy ipsec.AddressFamilyPolicy
		remote string
		want   error
	}{
		{"unknown", "127.0.0.1", ipsec.ErrInvalidAddressFamilyPolicy},
		{"ipv6-only", "127.0.0.1", ipsec.ErrAddressFamilyMismatch},
		{"ipv4-only", "::1", ipsec.ErrAddressFamilyMismatch},
	} {
		t.Run(string(test.policy), func(t *testing.T) {
			var calls atomic.Int32
			cfg := &Config{EpDGAddr: test.remote, EpDGPort: 4501, LocalAddr: "127.0.0.2", SourceIP: policyFamilySource,
				RemoteAddressFamily: test.policy, SIM: &diagnosticSIM{},
				SocketControl: func(string, string, syscall.RawConn) error { calls.Add(1); return nil }}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := NewSession(cfg, zap.NewNop()).Connect(ctx); !errors.Is(err, test.want) || calls.Load() != 0 {
				t.Fatalf("invalid policy did not reject before socket construction: %v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestRemoteAddressFamilyCannotBeBypassedByCustomFactoryOrMigration(t *testing.T) {
	marker := errors.New("custom transport invoked")
	for _, policy := range []ipsec.AddressFamilyPolicy{"", "prefer-ipv6"} {
		var calls atomic.Int32
		cfg := &Config{EpDGAddr: "::1", LocalAddr: "::1", RemoteAddressFamily: policy, SIM: &diagnosticSIM{},
			TransportFactory: func(string, string) (Transport, error) { calls.Add(1); return nil, marker }}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := NewSession(cfg, zap.NewNop()).Connect(ctx)
		cancel()
		if policy == "" {
			if !errors.Is(err, marker) || calls.Load() != 1 {
				t.Fatal("omitted policy changed custom transport compatibility")
			}
		} else if !errors.Is(err, ErrAddressFamilyPolicyTransport) || calls.Load() != 0 {
			t.Fatal("explicit family was silently delegated to an unqualified custom transport")
		}
	}
	session := NewSession(&Config{RemoteAddressFamily: "ipv6-only"}, zap.NewNop())
	session.mobikeSupported = true
	// This guards rejection before any migration message. It does not claim a
	// completed MOBIKE exchange or network/dataplane migration implementation.
	if err := session.UpdateAddresses("::1", "127.0.0.1"); !errors.Is(err, ErrAddressFamilyPolicyTransport) {
		t.Fatal("migration bypassed the explicit connect-only family policy")
	}
}

func TestRemoteAddressFamilyPreferenceFallsBackButOnlyPolicyDoesNot(t *testing.T) {
	for _, test := range []struct {
		policy ipsec.AddressFamilyPolicy
		answer string
		reject bool
	}{
		{"prefer-ipv6", "127.0.0.1", false}, {"prefer-ipv4", "::1", false},
		{"ipv6-only", "127.0.0.1", true}, {"ipv4-only", "::1", true},
	} {
		t.Run(string(test.policy), func(t *testing.T) {
			network := "udp4"
			if test.answer == "::1" {
				network = "udp6"
			}
			peer, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(test.answer)})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			dns, queries := familyDNS(t, "udp4", "127.0.0.1", net.ParseIP(test.answer))
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			remote := net.JoinHostPort("epdg.only-answer.invalid", fmt.Sprint(peer.LocalAddr().(*net.UDPAddr).Port))
			socket, err := ipsec.NewSocketManagerWithAddressFamily(ctx, "127.0.0.2:0", remote, dns, nil, policyFamilySource, nil, test.policy)
			if test.reject {
				if !errors.Is(err, ipsec.ErrAddressFamilyMismatch) || socket != nil || queries.Load() == 0 {
					t.Fatal("only policy silently widened the DNS result")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Stop()
			if !socket.RemoteIP().Equal(net.ParseIP(test.answer)) {
				t.Fatal("preference did not select the remaining compatible address")
			}
			if err := socket.SendIKE([]byte("family-probe")); err != nil {
				t.Fatal(err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			var wire [128]byte
			if n, _, err := peer.ReadFromUDP(wire[:]); err != nil || string(wire[:n]) != "family-probe" {
				t.Fatal("fallback selection did not reach the actual UDP peer")
			}
		})
	}
}

func TestRemoteAddressFamilyCanSelectIPv6WithUnboundSystemResolver(t *testing.T) {
	peer, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	dns, queries := familyDNS(t, "udp4", "127.0.0.1", net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dns)
	}}
	defer func() { net.DefaultResolver = previous }()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	remote := net.JoinHostPort("epdg.system-resolver.invalid", fmt.Sprint(peer.LocalAddr().(*net.UDPAddr).Port))
	socket, err := ipsec.NewSocketManagerWithAddressFamily(ctx, ":0", remote, "", nil, nil, nil, "prefer-ipv6")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Stop()
	if socket.RemoteIP().To4() != nil || !socket.RemoteIP().Equal(net.ParseIP("::1")) || queries.Load() == 0 {
		t.Fatal("explicit policy was lost in the default-resolver branch")
	}
	if err := socket.SendIKE([]byte("family-probe")); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var wire [128]byte
	if n, _, err := peer.ReadFromUDP(wire[:]); err != nil || string(wire[:n]) != "family-probe" {
		t.Fatal("default-resolver preference did not reach the actual IPv6 peer")
	}
}
