package swu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type interfaceMTUCall struct {
	iface string
	mtu   int
}

// Keep the existing route fixture; only add observations and a setter failure.
type interfaceMTUNet struct {
	familyRoutes
	mu        sync.Mutex
	setErr    error
	mtuCalls  []interfaceMTUCall
	addresses int
	routes    int
}

func (n *interfaceMTUNet) SetMTU(iface string, mtu int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mtuCalls = append(n.mtuCalls, interfaceMTUCall{iface, mtu})
	return n.setErr
}

func (n *interfaceMTUNet) AddAddress(iface, cidr string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addresses++
	return n.familyRoutes.AddAddress(iface, cidr)
}

func (n *interfaceMTUNet) AddAddress6(iface, cidr string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addresses++
	return n.familyRoutes.AddAddress6(iface, cidr)
}

func (n *interfaceMTUNet) AddRoute(cidr, gw, iface string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes++
	return n.familyRoutes.AddRoute(cidr, gw, iface)
}

func (n *interfaceMTUNet) AddRoute6(cidr, gw, iface string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes++
	return n.familyRoutes.AddRoute6(cidr, gw, iface)
}

func (n *interfaceMTUNet) observed() ([]interfaceMTUCall, int, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]interfaceMTUCall(nil), n.mtuCalls...), n.addresses, n.routes
}

type interfaceMTUTUN struct {
	mu         sync.Mutex
	done       chan struct{}
	closeErr   error
	closeCalls int
	closed     bool
}

func (t *interfaceMTUTUN) DeviceName() string          { return "mtu-test0" }
func (t *interfaceMTUTUN) Write(p []byte) (int, error) { return len(p), nil }
func (t *interfaceMTUTUN) Read([]byte) (int, error) {
	<-t.done
	return 0, io.EOF
}
func (t *interfaceMTUTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeCalls++
	if t.closeErr != nil {
		return t.closeErr
	}
	if !t.closed {
		t.closed = true
		close(t.done)
	}
	return nil
}

func (t *interfaceMTUTUN) closes() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeCalls
}

func (t *interfaceMTUTUN) failClose(err error) {
	t.mu.Lock()
	t.closeErr = err
	t.mu.Unlock()
}

func newInterfaceMTUDevices(t *testing.T, setErr error) (*interfaceMTUNet, *interfaceMTUTUN) {
	t.Helper()
	n := &interfaceMTUNet{setErr: setErr}
	tun := &interfaceMTUTUN{done: make(chan struct{})}
	t.Cleanup(func() { tun.failClose(nil); _ = tun.Close() })
	return n, tun
}

func newInterfaceMTUSession(t *testing.T, strict bool, mtu int, setErr error) (*Session, *interfaceMTUNet, *interfaceMTUTUN) {
	t.Helper()
	n, tun := newInterfaceMTUDevices(t, setErr)
	s, _ := newPostEAPSession(t, func(c *Config) {
		c.EnableDriver, c.DataplaneMode = true, "tun"
		c.TUNName, c.TUNMTU, c.RequireInterfaceMTU = tun.DeviceName(), mtu, strict
		c.NetTools = n
		c.TUNFactory = func(string) (TUN, error) { return tun, nil }
	})
	// Use a real authenticated initial Child selection, not a hand-built CP.
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, childTransactionPayloads(t, s), ikev2.IKE_AUTH, 3, true)); err != nil {
		t.Fatalf("initial Child fixture failed before MTU consumption: %v", err)
	}
	return s, n, tun
}

func assertInterfaceMTUCall(t *testing.T, n *interfaceMTUNet, mtu int) (int, int) {
	t.Helper()
	calls, addresses, routes := n.observed()
	if len(calls) != 1 || calls[0] != (interfaceMTUCall{"mtu-test0", mtu}) {
		t.Errorf("actual SetMTU calls = %+v; want one mtu-test0/%d", calls, mtu)
	}
	return addresses, routes
}

func TestInterfaceMTUStrictSetterFailureStopsBeforeNetworkConfig(t *testing.T) {
	// 1358 is deliberately identical to the compatibility factory's value.
	s, n, tun := newInterfaceMTUSession(t, true, 1358, syscall.EPERM)
	err := s.setupDataPlane()
	addresses, routes := assertInterfaceMTUCall(t, n, 1358)
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("SetMTU cause was swallowed: %v", err)
	}
	if addresses != 0 || routes != 0 {
		t.Errorf("network config ran after failed strict MTU: addresses=%d routes=%d", addresses, routes)
	}
	if tun.closes() != 1 || s.tun != nil {
		t.Errorf("failed strict TUN not closed/retired: closes=%d retained=%t", tun.closes(), s.tun != nil)
	}
}

func TestInterfaceMTULegacySetterFailureRemainsBestEffort(t *testing.T) {
	s, n, tun := newInterfaceMTUSession(t, false, 1358, syscall.EPERM)
	if err := s.setupDataPlane(); err != nil {
		t.Errorf("default false changed compatibility: %v", err)
	}
	addresses, routes := assertInterfaceMTUCall(t, n, 1358)
	if addresses == 0 || routes == 0 || s.tun != tun || tun.closes() != 0 {
		t.Error("best-effort control did not configure and retain its TUN")
	}
}

func TestInterfaceMTUStrictSetterSuccessUsesExactRequest(t *testing.T) {
	for _, mtu := range []int{1280, 1358, 1500} {
		t.Run(strconv.Itoa(mtu), func(t *testing.T) {
			s, n, tun := newInterfaceMTUSession(t, true, mtu, nil)
			if err := s.setupDataPlane(); err != nil {
				t.Errorf("successful strict setter rejected: %v", err)
			}
			addresses, routes := assertInterfaceMTUCall(t, n, mtu)
			if addresses == 0 || routes == 0 || s.tun != tun || tun.closes() != 0 {
				t.Error("successful setter did not reach existing network config")
			}
		})
	}
}

func TestInterfaceMTURequestIsCapturedBeforeCallerEditsConfig(t *testing.T) {
	for _, tc := range []struct {
		name       string
		strict     bool
		mtu        int
		changedMTU int
		setErr     error
	}{
		{"strict_value", true, 1400, 1280, nil},
		{"strict_requirement", true, 1358, 1358, syscall.EPERM},
		{"legacy_requirement", false, 1358, 1280, syscall.EPERM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, n, _ := newInterfaceMTUSession(t, tc.strict, tc.mtu, tc.setErr)
			// Sequential caller edits: never race a running Connect.
			s.cfg.RequireInterfaceMTU, s.cfg.TUNMTU = !tc.strict, tc.changedMTU
			err := s.setupDataPlane()
			assertInterfaceMTUCall(t, n, tc.mtu)
			if tc.strict && tc.setErr != nil {
				if !errors.Is(err, tc.setErr) {
					t.Errorf("captured strict requirement was lost: %v", err)
				}
			} else if err != nil {
				t.Errorf("captured request changed after caller edit: %v", err)
			}
		})
	}
}

func TestInterfaceMTUUnsupportedModesRejectBeforeTransport(t *testing.T) {
	for _, mode := range []string{"driver_disabled", "netstack"} {
		for _, strict := range []bool{true, false} {
			name := mode + "/legacy"
			if strict {
				name = mode + "/strict"
			}
			t.Run(name, func(t *testing.T) {
				attempts, ready := 0, 0
				dataplane := "tun"
				if mode == "netstack" {
					dataplane = "netstack"
				}
				s := NewSession(&Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", TUNMTU: 1358,
					RequireInterfaceMTU: strict, EnableDriver: mode == "netstack", DataplaneMode: dataplane,
					TransportFactory: func(_, _ string) (Transport, error) { attempts++; return nil, syscall.EADDRINUSE },
					OnReady:          func() { ready++ },
				}, zap.NewNop())
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				err := s.Connect(ctx)
				if strict {
					if attempts != 0 || err == nil || errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("unsupported strict mode reached transport: attempts=%d error=%v", attempts, err)
					}
				} else if attempts != 1 || !errors.Is(err, syscall.EADDRINUSE) {
					t.Errorf("legacy mode no longer reached its transport control: attempts=%d error=%v", attempts, err)
				}
				if ready != 0 {
					t.Error("failed connection invoked OnReady")
				}
			})
		}
	}
}

func TestInterfaceMTUInvalidStrictRequestDoesNotReachTransport(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		mtu        int
	}{
		{"zero", "tun", 0}, {"negative", "tun", -1}, {"unknown_mode", "invalid", 1358},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			cfg := &Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EnableDriver: true,
				RequireInterfaceMTU: true, TUNMTU: tc.mtu, DataplaneMode: tc.mode,
				TransportFactory: func(_, _ string) (Transport, error) { attempts++; return nil, syscall.EADDRINUSE }}
			s := NewSession(cfg, zap.NewNop())
			cfg.RequireInterfaceMTU, cfg.TUNMTU = false, 1358
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := s.Connect(ctx)
			if err == nil || errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, context.DeadlineExceeded) || attempts != 0 {
				t.Errorf("invalid captured strict request reached transport: attempts=%d error=%v", attempts, err)
			}
		})
	}
}

func TestInterfaceMTUAllocatedIPv6CannotReplaceAStrictRequest(t *testing.T) {
	for _, strict := range []bool{true, false} {
		name := "legacy_clamp"
		if strict {
			name = "strict_reject"
		}
		t.Run(name, func(t *testing.T) {
			s, n, tun := newInterfaceMTUSession(t, strict, 1279, nil)
			s.cpConfig.IPv6Addresses = []net.IP{net.ParseIP("2001:db8::10")}
			err := s.setupDataPlane()
			if strict {
				calls, addresses, routes := n.observed()
				if err == nil || len(calls) != 0 || addresses != 0 || routes != 0 || s.tun != nil || tun.closes() != 0 {
					t.Error("strict IPv6 minimum violation created an interface or silently changed the requested value")
				}
			} else {
				if err != nil {
					t.Errorf("legacy IPv6 clamp failed: %v", err)
				}
				assertInterfaceMTUCall(t, n, 1280)
			}
		})
	}
}

func TestInterfaceMTUCloseFailureRetainsCauseAndOwnedCleanup(t *testing.T) {
	s, n, tun := newInterfaceMTUSession(t, true, 1358, syscall.EPERM)
	tun.failClose(syscall.EIO)
	err := s.setupDataPlane()
	addresses, routes := assertInterfaceMTUCall(t, n, 1358)
	if !errors.Is(err, syscall.EPERM) || !errors.Is(err, syscall.EIO) {
		t.Errorf("setter or close cause was lost: %v", err)
	}
	if addresses != 0 || routes != 0 || tun.closes() != 1 || s.tun != tun || len(s.netUndos) == 0 {
		t.Error("failed close lost its owned TUN or pending cleanup")
	}
	err = s.cleanupNetworkConfig()
	if !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EIO) || s.tun != tun || len(s.netUndos) == 0 || tun.closes() != 2 {
		t.Errorf("failed cleanup discarded ownership or reported success: %v", err)
	}
	tun.failClose(nil)
	if err := s.cleanupNetworkConfig(); err != nil {
		t.Errorf("explicit retry did not finish owned close: %v", err)
	}
	if s.tun != nil || len(s.netUndos) != 0 || tun.closes() != 3 {
		t.Error("successful cleanup retry did not retire exactly its pending TUN")
	}
}

func TestInterfaceMTUConnectSetterFailureDoesNotPublishReady(t *testing.T) {
	for _, tc := range []struct {
		name   string
		strict bool
		setErr error
		pcscf  bool
	}{
		{"strict_failure", true, syscall.EPERM, true},
		{"legacy_failure", false, syscall.EPERM, true},
		{"strict_success", true, nil, true},
		{"strict_success_without_pcscf", true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := newAKAWirePeer(t)
			provider := &akaWireSIM{vectorSIM: vectorSIM{res: []byte{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67}, ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}}
			material := referenceAKAKeys(&provider.vectorSIM, false)
			n, tun := newInterfaceMTUDevices(t, tc.setErr)
			ready := make(chan struct{}, 1)
			var readyCalls atomic.Int32
			s := NewSession(&Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), APN: "ims", SIM: provider,
				EnableDriver: true, DataplaneMode: "tun", TUNName: tun.DeviceName(), TUNMTU: 1358, RequireInterfaceMTU: tc.strict,
				NetTools: n, TUNFactory: func(string) (TUN, error) { return tun, nil },
				OnReady: func() {
					readyCalls.Add(1)
					select {
					case ready <- struct{}{}:
					default:
					}
				},
			}, zap.NewNop())
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			done := make(chan error, 1)
			finished := false
			go func() { done <- s.Connect(ctx) }()
			t.Cleanup(func() {
				cancel()
				s.Shutdown()
				tun.failClose(nil)
				_ = tun.Close()
				if !finished {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("Connect owner did not terminate during cleanup")
					}
				}
			})
			// Independent existing AKA peer: validate AUTH, then reach the real setter.
			peer.negotiate(t)
			initial := peer.decrypt(t, peer.receive(t))
			assertAKAWireInitial(t, initial)
			idr := append([]byte{2, 0, 0, 0}, []byte(testIDrFQDN)...)
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 36, body: idr}, {kind: 48, body: referenceChallenge(material[16:32], false)}}))
			response := peer.decrypt(t, peer.receive(t))
			if len(response) != 1 || response[0].kind != 48 || !bytes.Equal(response[0].body, referenceResponse(provider.res, material[16:32], false)) {
				t.Fatal("independent AKA response differs before MTU setup")
			}
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{3, 0xa7, 0, 4}}}))
			final := peer.decrypt(t, peer.receive(t))
			key := independentHMACSHA256(material[32:96], []byte("Key Pad for IKEv2"))
			signed := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
			signed = append(signed, independentHMACSHA256(peer.keys[160:192], initial[0].body)...)
			if len(final) != 1 || final[0].kind != 39 || !bytes.Equal(final[0].body, append([]byte{2, 0, 0, 0}, independentHMACSHA256(key, signed)...)) {
				t.Fatal("initiator AUTH differs before MTU setup")
			}
			auth := independentResponderAUTH(material[32:96], peer.keys[192:224], idr, peer.initResponse, peer.initiatorNonce)
			child, err := testChildSA().Encode()
			if err != nil {
				t.Fatal(err)
			}
			cp := []byte{2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 10}
			if tc.pcscf {
				// A full-range TS does not add a direct route. Allocate a
				// requested P-CSCF when the success control requires a route.
				cp = append(cp, 0, 20, 0, 4, 198, 51, 100, 1)
			}
			peer.send(t, peer.protect(t, []akaWirePayload{
				{kind: 39, body: append([]byte{2, 0, 0, 0}, auth...)},
				{kind: 47, body: cp},
				{kind: 33, body: child},
				{kind: 44, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 192, 0, 2, 10, 192, 0, 2, 10}},
				{kind: 45, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255}},
			}))
			mustFail := tc.strict && tc.setErr != nil
			select {
			case err = <-done:
				finished = true
				if !mustFail {
					t.Errorf("setter compatibility/success control terminated before ready: %v", err)
				}
			case <-ready:
				if mustFail {
					t.Error("failed strict SetMTU published OnReady")
				} else if s.Snapshot().Security == nil {
					t.Error("successful control did not publish negotiated Security")
				}
				cancel()
			case <-ctx.Done():
				t.Fatal("authenticated MTU setup did not reach ready or return its setter failure")
			}
			if !finished {
				select {
				case err = <-done:
					finished = true
				case <-time.After(time.Second):
					t.Fatal("Connect did not return after cancellation")
				}
			}
			addresses, routes := assertInterfaceMTUCall(t, n, 1358)
			wantRoutes := 0
			if tc.pcscf {
				wantRoutes = 1
			}
			if mustFail {
				if !errors.Is(err, tc.setErr) || readyCalls.Load() != 0 || tun.closes() != 1 || s.tun != nil || addresses != 0 || routes != 0 {
					t.Errorf("strict setter failure did not retire before ready/network config: error=%v ready=%d close=%d addresses=%d routes=%d", err, readyCalls.Load(), tun.closes(), addresses, routes)
				}
				assertNoNegotiatedSecurity(t, s)
			} else if readyCalls.Load() != 1 || addresses != 1 || routes != wantRoutes {
				t.Errorf("control did not reach one real ready/network config: ready=%d addresses=%d routes=%d", readyCalls.Load(), addresses, routes)
			} else {
				t.Logf("ready=%d addresses=%d routes=%d allocated_pcscf=%t", readyCalls.Load(), addresses, routes, tc.pcscf)
			}
		})
	}
}
