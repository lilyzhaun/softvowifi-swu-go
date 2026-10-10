package swu

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func childTransactionPayloads(t *testing.T, s *Session) []ikev2.Payload {
	t.Helper()
	proposal := ikev2.NewProposal(3, ikev2.ProtoESP, []byte{0x22, 0x22, 0x22, 0x22})
	proposal.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256)
	proposal.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	proposal.AddTransform(ikev2.TransformTypeESN, 0, 0)
	return []ikev2.Payload{
		testIDrPayload(),
		&ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: independentResponderAUTH(s.MSK, s.Keys.SK_pr, mustIDrBody(t), s.saInitResp, s.ni)},
		&ikev2.EncryptedPayloadCP{CFGType: ikev2.CFG_REPLY, Attributes: []*ikev2.CPAttribute{
			{Type: ikev2.INTERNAL_IP4_ADDRESS, Value: []byte{192, 0, 2, 10}},
			{Type: ikev2.INTERNAL_IP4_DNS, Value: []byte{192, 0, 2, 53}},
			{Type: ikev2.P_CSCF_IP4_ADDRESS, Value: []byte{192, 0, 2, 9}},
		}},
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{proposal}},
		&ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4(net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 10), 0, 65535)}},
		&ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4(net.IPv4zero, net.IPv4(255, 255, 255, 255), 0, 65535)}},
	}
}

func TestInitialChildInvalidSelectionNeverCommitsState(t *testing.T) {
	for _, variant := range []string{"missing integrity", "CBC192", "wrong protocol", "zero SPI", "short SPI", "long SPI", "multiple proposals", "wrong number", "duplicate encr", "bad keylen attribute", "unknown attribute", "AEAD plus integrity", "unoffered GCM tag", "missing ESN", "unoffered ESN", "unoffered DH", "duplicate SA", "missing CP", "CP after SA", "request CP", "short CP address", "long CP address", "too many addresses", "bad IPv6 prefix", "wrong TSi host", "missing TSi", "missing TSr", "empty TSi", "reversed addresses", "reversed ports", "duplicate TSi", "duplicate CP", "malformed notify"} {
		t.Run(variant, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			s.peerIDrBody = nil
			payloads := childTransactionPayloads(t, s)
			cp := payloads[2].(*ikev2.EncryptedPayloadCP)
			sa := payloads[3].(*ikev2.EncryptedPayloadSA)
			p := sa.Proposals[0]
			tsi := payloads[4].(*ikev2.EncryptedPayloadTS)
			switch variant {
			case "missing integrity":
				p.Transforms = append(p.Transforms[:1], p.Transforms[2:]...)
			case "CBC192":
				p.Transforms[0].Attributes[0].Val = 192
			case "wrong protocol":
				p.ProtocolID = ikev2.ProtoIKE
			case "zero SPI":
				p.SPI = make([]byte, 4)
			case "short SPI":
				p.SPI = []byte{1, 2, 3}
			case "long SPI":
				p.SPI = []byte{1, 2, 3, 4, 5}
			case "multiple proposals":
				sa.Proposals = append(sa.Proposals, p)
			case "wrong number":
				p.ProposalNum = 1
			case "duplicate encr":
				p.Transforms = append(p.Transforms, p.Transforms[0])
			case "bad keylen attribute":
				p.Transforms[0].Attributes[0].Value = []byte{1, 0}
			case "unknown attribute":
				p.Transforms[0].Attributes = append(p.Transforms[0].Attributes, &ikev2.TransformAttribute{Type: 20, Val: 1})
			case "AEAD plus integrity":
				p.ProposalNum = 1
				p.Transforms[0].ID = ikev2.ENCR_AES_GCM_16
			case "unoffered GCM tag":
				p.ProposalNum = 1
				p.Transforms[0].ID = ikev2.ENCR_AES_GCM_12
				p.Transforms = append(p.Transforms[:1], p.Transforms[2:]...)
			case "missing ESN":
				p.Transforms = p.Transforms[:2]
			case "unoffered ESN":
				p.Transforms[2].ID = 1
			case "unoffered DH":
				p.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)
			case "duplicate SA":
				payloads = append(payloads, sa)
			case "missing CP":
				payloads = append(payloads[:2], payloads[3:]...)
			case "request CP":
				cp.CFGType = ikev2.CFG_REQUEST
			case "CP after SA":
				payloads[2], payloads[3] = payloads[3], payloads[2]
			case "short CP address":
				cp.Attributes[0].Value = []byte{192, 0, 2}
			case "long CP address":
				cp.Attributes[0].Value = []byte{192, 0, 2, 10, 0}
			case "too many addresses":
				cp.Attributes = append(cp.Attributes, &ikev2.CPAttribute{Type: ikev2.INTERNAL_IP4_ADDRESS, Value: []byte{192, 0, 2, 11}})
			case "bad IPv6 prefix":
				cp.Attributes = append(cp.Attributes, &ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: append(net.ParseIP("2001:db8::10").To16(), 129)})
			case "wrong TSi host":
				tsi.TrafficSelectors[0].StartAddr = []byte{192, 0, 2, 11}
				tsi.TrafficSelectors[0].EndAddr = []byte{192, 0, 2, 11}
			case "missing TSi":
				payloads = append(payloads[:4], payloads[5:]...)
			case "missing TSr":
				payloads = payloads[:5]
			case "empty TSi":
				tsi.TrafficSelectors = nil
			case "reversed addresses":
				tsi.TrafficSelectors[0].StartAddr = []byte{192, 0, 2, 11}
			case "reversed ports":
				tsi.TrafficSelectors[0].StartPort = 400
				tsi.TrafficSelectors[0].EndPort = 300
			case "duplicate TSi":
				payloads = append(payloads, tsi)
			case "duplicate CP":
				payloads = append(payloads, cp)
			case "malformed notify":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: []byte{1}})
			}
			payloads = append(payloads, mutationNotifies()[:3]...)
			before := snapPostEAP(s, *calls)
			raw := encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)
			err := s.handleIKEAuthFinalResp(raw)
			if err == nil {
				t.Fatal("invalid initial Child transaction accepted")
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
			if s.ChildSAIn != nil || s.ChildSAOut != nil || s.cpConfig != nil || len(s.tsi) != 0 || len(s.tsr) != 0 || len(s.childOutPolicies) != 0 || s.childEncrID != 0 || s.childIntegID != 0 || s.childESN {
				t.Fatal("invalid transaction committed Child/CP/TS/algorithms")
			}
		})
	}
}

func TestInitialChildLegalOriginalSuitesCommitTogether(t *testing.T) {
	for _, number := range []uint8{1, 2, 3, 4, 5, 6} {
		t.Run(string(rune('0'+number)), func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			s.peerIDrBody = nil
			payloads := childTransactionPayloads(t, s)
			spi := []byte{0x22, 0x22, 0x22, 0x22}
			p := ikev2.CreateMultiProposalESP(spi)[number-1]
			payloads[3] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{p}}
			payloads = append(payloads, mutationNotifies()[:3]...)
			seen := false
			s.cfg.OnTicketUpdate = func(ticket, skd []byte) {
				*calls++
				seen = s.ChildSAIn != nil && s.ChildSAOut != nil && s.cpConfig != nil && len(s.tsi) == 1 && len(s.tsr) == 1 && s.authLifetime == 3600 && s.mobikeSupported && bytes.Equal(s.peerIDrBody, mustIDrBody(t))
			}
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
				t.Fatal(err)
			}
			if !seen || *calls != 1 {
				t.Fatal("ticket callback observed partial Child/CP/TS/notify/transcript commit")
			}
			if s.ChildSAOut.SPI != binary.BigEndian.Uint32(spi) || s.ChildSAIn.SPI != s.childSPI || !s.cpConfig.IPv4Addresses[0].Equal(net.IPv4(192, 0, 2, 10)) || len(s.childOutPolicies) != 1 {
				t.Fatal("legal complete offer not committed")
			}
			if s.childEncrID != uint16(p.Transforms[0].ID) {
				t.Fatal("wrong accepted encryption transform")
			}
			expectedLen := []int{36, 20, 32, 16, 16, 32}[number-1]
			if len(s.ChildSAOut.EncryptionKey) != expectedLen || len(s.ChildSAIn.EncryptionKey) != expectedLen {
				t.Fatal("wrong accepted directional key lengths")
			}
		})
	}
}

func TestInitialChildTicketCallbackCannotMutateCommittedKeys(t *testing.T) {
	s, _ := newPostEAPSession(t)
	payloads := childTransactionPayloads(t, s)
	payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.TICKET_OPAQUE, NotifyData: []byte("synthetic-ticket")})
	skd := bytes.Clone(s.Keys.SK_d)
	s.cfg.OnTicketUpdate = func(ticket, key []byte) { ticket[0] ^= 1; key[0] ^= 1 }
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.resumeTicket, []byte("synthetic-ticket")) || !bytes.Equal(s.resumeOldSKd, skd) || !bytes.Equal(s.Keys.SK_d, skd) {
		t.Fatal("ticket callback mutated committed ticket/key material")
	}
}

func TestInitialChildSnapshotDoesNotAliasReturnedAUTH1(t *testing.T) {
	s, calls := newPostEAPSession(t)
	request, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range request {
		if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			sa.Proposals[2].Transforms[0].Attributes[0].Val = 192
		}
	}
	final := childTransactionPayloads(t, s)
	final[3].(*ikev2.EncryptedPayloadSA).Proposals[0].Transforms[0].Attributes[0].Val = 192
	before := snapPostEAP(s, *calls)
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, final, ikev2.IKE_AUTH, 3, true)); err == nil {
		t.Fatal("returned AUTH1 mutation changed immutable offered snapshot")
	}
	if !reflect.DeepEqual(before, snapPostEAP(s, *calls)) {
		t.Fatal("snapshot rejection committed state")
	}
}

func TestInitialChildDualStackAndExtraConfigurationRemainLegal(t *testing.T) {
	s, _ := newPostEAPSession(t)
	payloads := childTransactionPayloads(t, s)
	cp := payloads[2].(*ikev2.EncryptedPayloadCP)
	v6 := net.ParseIP("2001:db8::10").To16()
	cp.Attributes = append(cp.Attributes,
		&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: append(bytes.Clone(v6), 64)},
		&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_DNS, Value: net.ParseIP("2001:db8::53").To16()},
		&ikev2.CPAttribute{Type: ikev2.P_CSCF_IP6_ADDRESS, Value: net.ParseIP("2001:db8::9").To16()},
		&ikev2.CPAttribute{Type: ikev2.INTERNAL_IP4_NETMASK, Value: []byte{255, 255, 255, 0}},
		&ikev2.CPAttribute{Type: 32000, Value: []byte("ignored optional configuration")},
	)
	payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors = append(payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors, ikev2.NewTrafficSelectorIPV6(v6, v6, 0, 65535))
	max := bytes.Repeat([]byte{255}, 16)
	payloads[5].(*ikev2.EncryptedPayloadTS).TrafficSelectors = append(payloads[5].(*ikev2.EncryptedPayloadTS).TrafficSelectors, ikev2.NewTrafficSelectorIPV6(net.IPv6zero, max, 0, 65535))
	p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
	p.Transforms[0], p.Transforms[2] = p.Transforms[2], p.Transforms[0]
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
		t.Fatal(err)
	}
	if !s.cpConfig.IPv6Addresses[0].Equal(v6) || s.cpConfig.IPv6Prefix != 64 || len(s.tsi) != 2 || len(s.tsr) != 2 {
		t.Fatal("legal dual stack/reordered transforms lost state")
	}
}

func TestInitialChildSelectorsMustStayWithinFrozenRequest(t *testing.T) {
	for _, variant := range []string{"address", "ports", "protocol", "family"} {
		t.Run(variant, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			original, err := ikev2.DecodePacket(s.initialChildRequest)
			if err != nil {
				t.Fatal(err)
			}
			cp := original.Payloads[0].(*ikev2.EncryptedPayloadCP)
			sa := original.Payloads[1].(*ikev2.EncryptedPayloadSA)
			tsi := original.Payloads[2].(*ikev2.EncryptedPayloadTS)
			tsr := original.Payloads[3].(*ikev2.EncryptedPayloadTS)
			selector := ikev2.NewTrafficSelectorIPV4(net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 10), 100, 200)
			selector.IPProtocol = 6
			tsi.TrafficSelectors = []*ikev2.TrafficSelector{selector}
			if err := s.snapshotInitialChildRequest(cp, sa, tsi, tsr); err != nil {
				t.Fatal(err)
			}
			final := childTransactionPayloads(t, s)
			selected := final[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0]
			selected.StartPort, selected.EndPort, selected.IPProtocol = 100, 200, 6
			switch variant {
			case "address":
				selected.StartAddr = []byte{192, 0, 2, 9}
			case "ports":
				selected.EndPort = 201
			case "protocol":
				selected.IPProtocol = 17
			case "family":
				final[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::10"), 100, 200)}
			}
			before := snapPostEAP(s, *calls)
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, final, ikev2.IKE_AUTH, 3, true)); err == nil {
				t.Fatal("selection broadened frozen TS request")
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
		})
	}
}
