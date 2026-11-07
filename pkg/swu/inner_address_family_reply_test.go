package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

// Reuse the independently authenticated final-AUTH transaction fixture; only
// select its allocation and selector family, never inject a request snapshot.
func innerFamilyReply(t *testing.T, s *Session, ipv6 bool) []ikev2.Payload {
	t.Helper()
	payloads := childTransactionPayloads(t, s)
	cp := payloads[2].(*ikev2.EncryptedPayloadCP)
	if ipv6 {
		address := net.ParseIP("2001:db8::10").To16()
		cp.Attributes = []*ikev2.CPAttribute{
			{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: append(bytes.Clone(address), 64)},
			{Type: ikev2.INTERNAL_IP6_DNS, Value: net.ParseIP("2001:db8::53").To16()},
			{Type: ikev2.P_CSCF_IP6_ADDRESS, Value: net.ParseIP("2001:db8::9").To16()},
			// Legal unrequested inactive-family server attributes are filtered,
			// not confused with an unrequested address allocation.
			{Type: ikev2.INTERNAL_IP4_DNS, Value: []byte{192, 0, 2, 53}},
			{Type: ikev2.P_CSCF_IP4_ADDRESS, Value: []byte{192, 0, 2, 9}},
		}
		payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(address, address, 0, 65535)}
		payloads[5].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.IPv6zero, bytes.Repeat([]byte{255}, 16), 0, 65535)}
	} else {
		cp.Attributes = append(cp.Attributes,
			&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_DNS, Value: net.ParseIP("2001:db8::53").To16()},
			&ikev2.CPAttribute{Type: ikev2.P_CSCF_IP6_ADDRESS, Value: net.ParseIP("2001:db8::9").To16()})
	}
	return payloads
}

func TestInnerAddressFamilyAuthenticatedReply(t *testing.T) {
	for _, family := range []string{"", "dual-stack", "ipv4", "ipv6"} {
		for _, ipv6 := range []bool{false, true} {
			if family == "ipv4" && ipv6 || family == "ipv6" && !ipv6 {
				continue
			}
			name := family + "/allocation=ipv4"
			if ipv6 {
				name = family + "/allocation=ipv6"
			}
			t.Run(name, func(t *testing.T) {
				s, _ := newPostEAPSession(t, func(c *Config) { c.InnerAddressFamily = family })
				payloads := innerFamilyReply(t, s, ipv6)
				if family == "" || family == "dual-stack" {
					// Legal dual-stack partial allocation may return a valid
					// inactive selector. It must never become runtime policy.
					other := innerFamilyReply(t, s, !ipv6)
					for _, index := range []int{4, 5} {
						ts := payloads[index].(*ikev2.EncryptedPayloadTS)
						ts.TrafficSelectors = append(ts.TrafficSelectors, other[index].(*ikev2.EncryptedPayloadTS).TrafficSelectors...)
					}
				}
				if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
					t.Fatal(err)
				}
				if s.ChildSAIn == nil || s.ChildSAOut == nil || s.cpConfig == nil || len(s.tsi) != 1 || len(s.tsr) != 1 || len(s.childOutPolicies) != 1 {
					t.Fatal("legal selection did not commit complete Child/CP/TS")
				}
				want := uint8(ikev2.TS_IPV4_ADDR_RANGE)
				if ipv6 {
					want = ikev2.TS_IPV6_ADDR_RANGE
				}
				if s.tsi[0].TSType != want || s.tsr[0].TSType != want || len(s.childOutPolicies[0].tsr) != 1 {
					t.Fatal("inactive selectors entered runtime Child policy")
				}
				if ipv6 && (len(s.cpConfig.IPv4Addresses)+len(s.cpConfig.IPv4DNS)+len(s.cpConfig.IPv4PCSCF) != 0) || !ipv6 && (len(s.cpConfig.IPv6Addresses)+len(s.cpConfig.IPv6DNS)+len(s.cpConfig.IPv6PCSCF) != 0) {
					t.Fatal("inactive addresses/servers entered runtime CP")
				}
				routes := &familyRoutes{}
				s.net = routes
				if err := s.applyNetworkConfigOnTUN("inner-family-test0"); err != nil {
					t.Fatal(err)
				}
				if ipv6 && (len(routes.v4) != 0 || len(routes.v6) == 0) || !ipv6 && (len(routes.v6) != 0 || len(routes.v4) == 0) {
					t.Fatal("inactive family entered route consumer")
				}
			})
		}
	}
}

func TestInnerAddressFamilyRejectedReplyNeverCommits(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6", "dual-stack"} {
		for _, variant := range []string{"other allocation", "other TSi", "other TSr", "no allocated address", "empty active TSi", "malformed inactive TS"} {
			if family == "dual-stack" && (variant == "other allocation" || variant == "other TSi" || variant == "other TSr") {
				continue
			}
			t.Run(family+"/"+variant, func(t *testing.T) {
				s, calls := newPostEAPSession(t, func(c *Config) { c.InnerAddressFamily = family })
				payloads := innerFamilyReply(t, s, family == "ipv6")
				other := innerFamilyReply(t, s, family != "ipv6")
				cp := payloads[2].(*ikev2.EncryptedPayloadCP)
				switch variant {
				case "other allocation":
					cp.Attributes = append(cp.Attributes, other[2].(*ikev2.EncryptedPayloadCP).Attributes[0])
				case "other TSi":
					payloads[4] = other[4]
				case "other TSr":
					payloads[5] = other[5]
				case "no allocated address":
					cp.Attributes = cp.Attributes[1:]
				case "empty active TSi":
					payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors = nil
				case "malformed inactive TS":
					ts := other[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0]
					ts.StartPort, ts.EndPort = 400, 300
					i := payloads[4].(*ikev2.EncryptedPayloadTS)
					i.TrafficSelectors = append(i.TrafficSelectors, ts)
				}
				payloads = append(payloads, mutationNotifies()[:3]...)
				before := snapPostEAP(s, *calls)
				if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); !errors.Is(err, errInitialChild) {
					t.Fatalf("reply did not reach authenticated Child CP/TS rejection: %v", err)
				} else {
					t.Logf("authenticated Child CP/TS rejection: %v", err)
				}
				assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
				if s.ChildSAIn != nil || s.ChildSAOut != nil || s.cpConfig != nil || len(s.tsi)+len(s.tsr)+len(s.childOutPolicies) != 0 || s.childEncrID != 0 || s.childIntegID != 0 || s.childESN {
					t.Fatal("rejected reply committed Child/CP/TS/algorithms")
				}
			})
		}
	}
}

type innerFamilySIM struct{ reads, auth int }

func (s *innerFamilySIM) GetIMSI() (string, error) { s.reads++; return "001010000000001", nil }
func (s *innerFamilySIM) CalculateAKA([]byte, []byte) ([]byte, []byte, []byte, []byte, error) {
	s.auth++
	return nil, nil, nil, nil, errors.New("unexpected synthetic authentication")
}
func (*innerFamilySIM) Close() error { return nil }

func TestInnerAddressFamilyInvalidBeforeNetworkAndSIM(t *testing.T) {
	for _, family := range []string{"IPv4", "ipv4-only", "prefer-ipv4", " ipv6", "ipv6 ", "unknown-sensitive-value"} {
		for _, endpoint := range []string{"127.0.0.1", "epdg.example.test"} {
			t.Run(family+"/"+endpoint, func(t *testing.T) {
				provider := &innerFamilySIM{}
				networkCalls := 0
				cfg := &Config{InnerAddressFamily: family, SIM: provider, EpDGAddr: endpoint, EpDGPort: 500, LocalAddr: "127.0.0.1", DNSServer: "127.0.0.1:53"}
				cfg.SocketControl = func(string, string, syscall.RawConn) error {
					networkCalls++
					return errors.New("unexpected socket or DNS access")
				}
				s := NewSession(cfg, zap.NewNop())
				cfg.InnerAddressFamily = "ipv4"
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := s.Connect(ctx); !errors.Is(err, ErrInvalidInnerAddressFamily) || err.Error() != "invalid inner address family" {
					t.Fatalf("invalid captured policy did not return safe API error: %v", err)
				}
				if _, err := s.buildIKEAuthInitPayloads(); !errors.Is(err, ErrInvalidInnerAddressFamily) {
					t.Fatalf("direct AUTH builder bypassed invalid policy: %v", err)
				}
				if networkCalls+provider.reads+provider.auth != 0 || len(s.initialChildRequest) != 0 {
					t.Fatal("invalid policy used network/DNS/SIM or captured a request")
				}
			})
		}
	}
}
