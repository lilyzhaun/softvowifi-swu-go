package swu

import (
	"bytes"
	"net"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/iniwex5/netlink"
)

func partialFamilyPayloads(t *testing.T, s *Session, ipv6 bool) []ikev2.Payload {
	t.Helper()
	payloads := childTransactionPayloads(t, s)
	cp := payloads[2].(*ikev2.EncryptedPayloadCP)
	v6 := net.ParseIP("2001:db8::10").To16()
	if ipv6 {
		cp.Attributes[0] = &ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: append(bytes.Clone(v6), 64)}
	}
	cp.Attributes = append(cp.Attributes, &ikev2.CPAttribute{Type: ikev2.P_CSCF_IP6_ADDRESS, Value: net.ParseIP("2001:db8::9").To16()})
	for _, index := range []int{4, 5} {
		ts := payloads[index].(*ikev2.EncryptedPayloadTS)
		ts.TrafficSelectors = append(ts.TrafficSelectors,
			ikev2.NewTrafficSelectorIPV6(net.IPv6zero, bytes.Repeat([]byte{255}, 16), 0, 65535))
	}
	return payloads
}

func TestInitialChildPartialAllocationUsesOnlyUsableFamily(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		family := uint8(ikev2.TS_IPV4_ADDR_RANGE)
		if ipv6 {
			name, family = "IPv6", ikev2.TS_IPV6_ADDR_RANGE
		}
		t.Run(name, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			payloads := partialFamilyPayloads(t, s, ipv6)
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
				t.Fatalf("valid partial dual-stack allocation rejected: %v", err)
			}
			if len(s.tsi) != 1 || len(s.tsr) != 1 || s.tsi[0].TSType != family || s.tsr[0].TSType != family {
				t.Fatal("unallocated selector family leaked into runtime state")
			}
			if len(s.childOutPolicies) != 1 || len(s.childOutPolicies[0].tsr) != 1 {
				t.Fatal("unallocated family leaked into child outbound policy")
			}
			if got := s.Snapshot(); ipv6 && (got.IPv4 != nil || got.IPv6 == nil) || !ipv6 && (got.IPv4 == nil || got.IPv6 != nil) {
				t.Fatal("snapshot advertised an unallocated source family")
			}
		})
	}
}

func TestInitialChildPartialAllocationPreservesNegativeInvariants(t *testing.T) {
	for _, variant := range []string{"all unallocated", "foreign allocated host", "invalid inactive range", "inactive TS outside request", "no destination family"} {
		t.Run(variant, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			payloads := partialFamilyPayloads(t, s, true)
			i := payloads[4].(*ikev2.EncryptedPayloadTS)
			r := payloads[5].(*ikev2.EncryptedPayloadTS)
			switch variant {
			case "all unallocated":
				i.TrafficSelectors = i.TrafficSelectors[:1]
			case "foreign allocated host":
				i.TrafficSelectors[1].StartAddr = net.ParseIP("2001:db8::11").To16()
				i.TrafficSelectors[1].EndAddr = bytes.Clone(i.TrafficSelectors[1].StartAddr)
			case "invalid inactive range":
				i.TrafficSelectors[0].StartPort, i.TrafficSelectors[0].EndPort = 400, 300
			case "inactive TS outside request":
				i.TrafficSelectors[0].IPProtocol = 17
				request, err := ikev2.DecodePacket(s.initialChildRequest)
				if err != nil {
					t.Fatal(err)
				}
				originalI := request.Payloads[2].(*ikev2.EncryptedPayloadTS)
				originalI.TrafficSelectors[0].IPProtocol = 6
				if err := s.snapshotInitialChildRequest(request.Payloads[0].(*ikev2.EncryptedPayloadCP), request.Payloads[1].(*ikev2.EncryptedPayloadSA), originalI, request.Payloads[3].(*ikev2.EncryptedPayloadTS)); err != nil {
					t.Fatal(err)
				}
			case "no destination family":
				r.TrafficSelectors = r.TrafficSelectors[:1]
			}
			payloads = append(payloads, mutationNotifies()[:3]...)
			before := snapPostEAP(s, *calls)
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err == nil {
				t.Fatal("partial allocation bypassed a negative invariant")
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
			if s.cpConfig != nil || s.ChildSAIn != nil || len(s.tsi) != 0 || len(s.tsr) != 0 {
				t.Fatal("invalid partial allocation committed state")
			}
		})
	}
}

func TestInitialChildRekeyKeepsOnlyAllocatedPolicyFamily(t *testing.T) {
	s, next := rekeyXFRMFixture()
	s.cpConfig = &ikev2.CPConfig{IPv6Addresses: []net.IP{net.ParseIP("2001:db8::10")}}
	s.tsi = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::10"), 0, 65535)}
	s.tsr = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.IPv6zero, bytes.Repeat([]byte{255}, 16), 0, 65535)}
	kernel := newRekeyKernel()
	if err := s.rekeyXFRM(kernel, next, [2]uint32{101, 102}); err != nil {
		t.Fatal(err)
	}
	if len(kernel.policies) != 2 {
		t.Fatal("rekey reinstalled unallocated IPv4 policy family")
	}
	for _, policy := range kernel.policies {
		if policy.Src.IP.To4() != nil || policy.Dst.IP.To4() != nil {
			t.Fatal("IPv4 policy leaked after IPv6-only allocation")
		}
	}
}

type familyRoutes struct{ v4, v6 []string }

func (*familyRoutes) SetLinkUp(string) error                   { return nil }
func (*familyRoutes) SetMTU(string, int) error                 { return nil }
func (n *familyRoutes) AddAddress(_ string, cidr string) error { n.v4 = append(n.v4, cidr); return nil }
func (n *familyRoutes) AddAddress6(_ string, cidr string) error {
	n.v6 = append(n.v6, cidr)
	return nil
}
func (n *familyRoutes) AddRoute(cidr, _, _ string) error  { n.v4 = append(n.v4, cidr); return nil }
func (n *familyRoutes) AddRoute6(cidr, _, _ string) error { n.v6 = append(n.v6, cidr); return nil }

func TestInitialChildNetworkConfigCannotRouteUnallocatedFamily(t *testing.T) {
	s, _ := newPostEAPSession(t)
	s.cpConfig = &ikev2.CPConfig{IPv6Addresses: []net.IP{net.ParseIP("2001:db8::10")}, IPv4PCSCF: []net.IP{net.IPv4(192, 0, 2, 9)}, IPv6PCSCF: []net.IP{net.ParseIP("2001:db8::9")}}
	s.tsi = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::10"), 0, 65535)}
	s.tsr = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.IPv6zero, bytes.Repeat([]byte{255}, 16), 0, 65535)}
	n := &familyRoutes{}
	s.net = n
	if err := s.applyNetworkConfigOnTUN("synthetic0"); err != nil {
		t.Fatal(err)
	}
	if len(n.v4) != 0 || len(n.v6) == 0 {
		t.Fatal("network config used an unallocated family")
	}
}

func TestInitialChildXFRMPolicyBuilderKeepsOnlyUsableFamilies(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		s, _ := newPostEAPSession(t)
		payloads := partialFamilyPayloads(t, s, ipv6)
		if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
			t.Fatal(err)
		}
		s.xfrmLocalIP, s.xfrmRemoteIP = net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)
		s.xfrmIfID = 37
		policies := s.initialChildXFRMPolicies()
		want := 3
		if ipv6 {
			want = 2
		}
		if len(policies) != want {
			t.Fatal("initial policy builder included an inactive family")
		}
		for _, policy := range policies {
			if (policy.Src.IP.To4() == nil) != ipv6 || (policy.Dst.IP.To4() == nil) != ipv6 {
				t.Fatal("unallocated family installed")
			}
			if policy.Ifid != 37 || policy.TmplProto != netlink.XFRM_PROTO_ESP || policy.TmplMode != netlink.XFRM_MODE_TUNNEL {
				t.Fatal("bound mandatory outer template changed")
			}
			switch policy.Dir {
			case netlink.XFRM_DIR_OUT:
				if policy.TmplSPI != int(s.ChildSAOut.SPI) || !policy.TmplSrc.Equal(s.xfrmLocalIP) || !policy.TmplDst.Equal(s.xfrmRemoteIP) {
					t.Fatal("outgoing template direction changed")
				}
			case netlink.XFRM_DIR_IN:
				if policy.TmplSPI != int(s.ChildSAIn.SPI) || !policy.TmplSrc.Equal(s.xfrmRemoteIP) || !policy.TmplDst.Equal(s.xfrmLocalIP) {
					t.Fatal("incoming template direction changed")
				}
			case netlink.XFRM_DIR_FWD:
				if ipv6 || policy.TmplSPI != 0 {
					t.Fatal("forward policy compatibility changed")
				}
			default:
				t.Fatal("unexpected direction")
			}
		}
	}
}
