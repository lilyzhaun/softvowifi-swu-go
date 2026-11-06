package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/iniwex5/netlink"
)

type interfaceMTUKernelNet struct {
	NetTools // Real direct-route fallback; avoid the concrete-driver policy-router assertion.
	netToolsDeleter
	setErr            error
	calls             []interfaceMTUCall
	addresses, routes int
}

func (n *interfaceMTUKernelNet) SetMTU(iface string, mtu int) error {
	n.calls = append(n.calls, interfaceMTUCall{iface, mtu})
	if n.setErr != nil {
		return n.setErr
	}
	return n.NetTools.SetMTU(iface, mtu)
}
func (n *interfaceMTUKernelNet) AddAddress(iface, cidr string) error {
	n.addresses++
	return n.NetTools.AddAddress(iface, cidr)
}
func (n *interfaceMTUKernelNet) AddAddress6(iface, cidr string) error {
	n.addresses++
	return n.NetTools.AddAddress6(iface, cidr)
}
func (n *interfaceMTUKernelNet) AddRoute(cidr, gw, iface string) error {
	n.routes++
	return n.NetTools.AddRoute(cidr, gw, iface)
}
func (n *interfaceMTUKernelNet) AddRoute6(cidr, gw, iface string) error {
	n.routes++
	return n.NetTools.AddRoute6(cidr, gw, iface)
}

func TestInterfaceMTUKernelXFRMFailureAndOwnedCleanup(t *testing.T) {
	if os.Getenv("ISSUE33_KERNEL_TEST") != "1" {
		t.Skip("requires explicit isolated child namespace")
	}
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	must(t, err)
	if parent := os.Getenv("ISSUE33_PARENT_NETNS"); parent == "" || parent == ns {
		t.Fatal("refusing unisolated kernel operations")
	}
	const ownName, foreignName, ownID, foreignID = "mtu-owned0", "mtu-canary0", 0x790, 0x791
	inventory := func(t *testing.T, saCount, spCount int) ([]netlink.XfrmState, []netlink.XfrmPolicy) {
		t.Helper()
		states, stateErr := netlink.XfrmStateList(netlink.FAMILY_ALL)
		policies, policyErr := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
		if stateErr != nil || policyErr != nil || len(states) != saCount || len(policies) != spCount {
			t.Fatalf("unexpected isolated SA/SP inventory: %d/%d errors=%v/%v", len(states), len(policies), stateErr, policyErr)
		}
		return states, policies
	}
	noLink := func(t *testing.T, name string) {
		t.Helper()
		_, err := netlink.LinkByName(name)
		var absent netlink.LinkNotFoundError
		if !errors.As(err, &absent) {
			t.Errorf("test link %s is not confirmed absent: %v", name, err)
		}
	}
	inventory(t, 0, 0)
	noLink(t, ownName)
	noLink(t, foreignName)
	if t.Failed() {
		return // Never let the production interface constructor replace a foreign link.
	}
	lo, err := netlink.LinkByName("lo")
	must(t, err)
	must(t, netlink.LinkSetUp(lo))
	canary, canaryLink := driver.NewXFRMManager(), false
	t.Cleanup(func() {
		if err := canary.CleanupOwned(); err != nil {
			t.Error(err)
		}
		if canaryLink {
			if err := canary.DelXFRMInterface(foreignName); err != nil {
				t.Error(err)
			}
		}
		inventory(t, 0, 0)
		noLink(t, ownName)
		noLink(t, foreignName)
	})
	must(t, canary.AddXFRMInterface(foreignName, foreignID, lo.Attrs().Index))
	canaryLink = true
	must(t, driver.NewNetTools().SetMTU(foreignName, 1440))
	foreign := driver.XFRMSAConfig{Src: net.IPv4(127, 0, 0, 3), Dst: net.IPv4(127, 0, 0, 4), SPI: 0x71717171,
		Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL, Ifid: foreignID, SADir: netlink.XFRM_SA_DIR_OUT,
		CryptAlgoName: "cbc(aes)", CryptKey: bytes.Repeat([]byte{0x31}, 16), AuthAlgoName: "hmac(sha256)", AuthKey: bytes.Repeat([]byte{0x42}, 32), AuthTruncLen: 128}
	must(t, canary.AddSA(foreign))
	must(t, canary.AddSP(driver.XFRMSPConfig{
		Src: &net.IPNet{IP: net.IPv4(198, 51, 100, 1), Mask: net.CIDRMask(32, 32)}, Dst: &net.IPNet{IP: net.IPv4(198, 51, 100, 2), Mask: net.CIDRMask(32, 32)},
		Dir: netlink.XFRM_DIR_OUT, Ifid: foreignID, TmplSrc: foreign.Src, TmplDst: foreign.Dst, TmplProto: foreign.Proto, TmplMode: foreign.Mode, TmplSPI: int(foreign.SPI),
	}))
	beforeSA, beforeSP := inventory(t, 1, 1)
	beforeLink, err := netlink.LinkByName(foreignName)
	must(t, err)
	checkCanary := func(t *testing.T) {
		t.Helper()
		sa, saErr := netlink.XfrmStateGet(&beforeSA[0])
		sp, spErr := netlink.XfrmPolicyGet(&beforeSP[0])
		link, linkErr := netlink.LinkByName(foreignName)
		if saErr != nil || spErr != nil || linkErr != nil || !reflect.DeepEqual(sa, &beforeSA[0]) || !reflect.DeepEqual(sp, &beforeSP[0]) || !reflect.DeepEqual(link, beforeLink) {
			t.Error("foreign canary SA/SP/link changed (full structures compared without printing keys or addresses)")
		}
	}
	for _, tc := range []struct {
		name   string
		strict bool
		setErr error
	}{{"strict_failure", true, syscall.EPERM}, {"legacy_failure", false, syscall.EPERM}, {"strict_success", true, nil}} {
		if !t.Run(tc.name, func(t *testing.T) {
			s, _, tun := newInterfaceMTUSession(t, tc.strict, 1358, nil)
			s.ctx, s.cancel = context.WithCancel(t.Context())
			var restore *netlink.XfrmState
			t.Cleanup(func() {
				defer s.cancel()
				if restore != nil {
					if err := netlink.XfrmStateUpdate(restore); err != nil {
						t.Error("restore owned SA before cleanup:", err)
					}
				}
				if err := s.cleanupNetworkConfig(); err != nil {
					t.Error(err)
				}
				checkCanary(t)
				noLink(t, ownName)
				inventory(t, 1, 1)
			})
			realNet := driver.NewNetTools()
			n := &interfaceMTUKernelNet{NetTools: realNet, netToolsDeleter: realNet, setErr: tc.setErr}
			s.cfg.DataplaneMode, s.cfg.TUNName, s.cfg.XFRMIfID, s.cfg.ReplayWindow = "xfrmi", ownName, ownID, 0 // OUT0/IN32, not a product-default change.
			s.cfg.NetTools, s.net = n, n
			s.cfg.RequireInterfaceMTU, s.cfg.TUNMTU = !tc.strict, 1280 // Both captured; mode/tools above are direct kernel fixture inputs.
			socket, err := ipsec.NewSocketManagerWithObserver(s.ctx, "127.0.0.1:0", "127.0.0.2:4500", "", nil, nil, nil)
			must(t, err)
			s.socket = socket
			t.Cleanup(socket.Stop)
			socket.Start()
			// Real authenticated Child/CP/TS and kernel bootstrap, not full AKA/Connect/OnReady or MOBIKE/Android evidence.
			err = s.setupXFRMDataPlane()
			if tc.strict && tc.setErr != nil {
				if !errors.Is(err, syscall.EPERM) || n.addresses != 0 || n.routes != 0 {
					t.Errorf("strict setter failure lost cause or configured network: %v", err)
				}
			} else if err != nil || n.addresses == 0 || n.routes == 0 {
				t.Errorf("compatibility/success did not configure the real network: %v", err)
			}
			if !reflect.DeepEqual(n.calls, []interfaceMTUCall{{ownName, 1358}}) || s.tun != nil || tun.closes() != 0 {
				t.Fatal("kernel bootstrap did not consume exactly the captured MTU without using fake TUN")
			}
			inventory(t, 3, 4) // Owned two-way SA + OUT/IN/FWD policies, alongside the independent canary.
			var original *netlink.XfrmState
			for i, sa := range []*ipsec.SecurityAssociation{s.ChildSAOut, s.ChildSAIn} {
				state, err := netlink.XfrmStateGet(&netlink.XfrmState{Dst: []net.IP{net.IPv4(127, 0, 0, 2), net.IPv4(127, 0, 0, 1)}[i], Spi: int(sa.SPI), Proto: netlink.XFRM_PROTO_ESP})
				if err != nil || state.Ifid != ownID || state.ReplayWindow != []int{0, 32}[i] ||
					state.Crypt == nil || state.Auth == nil || !bytes.Equal(state.Crypt.Key, sa.EncryptionKey) || !bytes.Equal(state.Auth.Key, sa.IntegrityKey) {
					t.Fatal("real two-way SA does not match authenticated Child keys, replay or owner")
				}
				// Some retained kernels do not report the optional SA direction.
				// Roles remain bound by actual SPI, endpoint, keys and if_id; this
				// MTU test must not claim Linux7 direction-metadata coverage.
				if state.SADir == 0 {
					t.Log("SA direction metadata unavailable; not direction-metadata verification")
				} else if state.SADir != []netlink.SADir{netlink.XFRM_SA_DIR_OUT, netlink.XFRM_SA_DIR_IN}[i] {
					t.Fatal("reported SA direction differs from its selected Child role")
				}
				if i == 0 {
					original = state
				}
			}
			checkCanary(t)
			if tc.setErr == nil {
				link, err := netlink.LinkByName(ownName)
				if err != nil || link.Attrs().MTU != 1358 {
					t.Fatal("independent bootstrap GET did not confirm the requested interface MTU")
				}
			}
			if tc.strict && tc.setErr != nil {
				restore = original // Registered restoration survives every subsequent Fatal.
				changed := *original
				changed.Limits.TimeHard += 3600
				must(t, netlink.XfrmStateUpdate(&changed))
				undoCount := len(s.netUndos)
				err := s.cleanupNetworkConfig()
				if !errors.Is(err, ErrCleanup) || !errors.Is(err, driver.ErrOwnershipChanged) || undoCount == 0 || len(s.netUndos) != undoCount {
					t.Errorf("failed owned cleanup lost its error or pending network responsibility: %v", err)
				}
				drifted, stateErr := netlink.XfrmStateGet(original)
				_, linkErr := netlink.LinkByName(ownName)
				if stateErr != nil || drifted.Ifid != ownID || drifted.Limits.TimeHard != changed.Limits.TimeHard || linkErr != nil {
					t.Fatal("failed cleanup removed the drifted owned SA or pending owned link")
				}
				checkCanary(t) // Other owned SA/SP may already have been removed; never require the full pair here.
				must(t, netlink.XfrmStateUpdate(original))
				restore = nil
			}
			if err := s.cleanupNetworkConfig(); err != nil || len(s.netUndos) != 0 {
				t.Fatalf("explicit owned cleanup retry failed or retained responsibility: %v", err)
			}
		}) {
			break // Do not replace resources retained by a failed preceding owner.
		}
	}
}
