package swu

import (
	"bytes"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func initSelectionFixture(t *testing.T) (*Session, *ikev2.IKEPacket) {
	t.Helper()
	sess := newInitTestSession("")
	raw, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	sa, ke, _ := decodeInitSA(t, raw)
	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = sess.SPIi
	packet.Header.SPIr = 1234
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagResponse
	packet.Payloads = []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: sa.Proposals[:1]}, ke,
		&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{9}, 32)},
	}
	return sess, packet
}

func Test_InitRejectsSelection_whenResponseNotBoundToOffer(t *testing.T) {
	cases := map[string]func(*ikev2.IKEPacket){
		"initiator SPI":      func(p *ikev2.IKEPacket) { p.Header.SPIi++ },
		"zero responder SPI": func(p *ikev2.IKEPacket) { p.Header.SPIr = 0 },
		"flags":              func(p *ikev2.IKEPacket) { p.Header.Flags |= ikev2.FlagInitiator },
		"message ID":         func(p *ikev2.IKEPacket) { p.Header.MessageID = 1 },
		"major version":      func(p *ikev2.IKEPacket) { p.Header.Version = 0x30 },
		"exchange":           func(p *ikev2.IKEPacket) { p.Header.ExchangeType = ikev2.IKE_AUTH },
		"missing SA":         func(p *ikev2.IKEPacket) { p.Payloads = p.Payloads[1:] },
		"extra SA":           func(p *ikev2.IKEPacket) { p.Payloads = append(p.Payloads, p.Payloads[0]) },
		"extra KE":           func(p *ikev2.IKEPacket) { p.Payloads = append(p.Payloads, p.Payloads[1]) },
		"extra nonce":        func(p *ikev2.IKEPacket) { p.Payloads = append(p.Payloads, p.Payloads[2]) },
		"short nonce":        func(p *ikev2.IKEPacket) { p.Payloads[2].(*ikev2.EncryptedPayloadNonce).NonceData = []byte{1} },
		"long nonce":         func(p *ikev2.IKEPacket) { p.Payloads[2].(*ikev2.EncryptedPayloadNonce).NonceData = make([]byte, 257) },
		"KE group":           func(p *ikev2.IKEPacket) { p.Payloads[1].(*ikev2.EncryptedPayloadKE).DHGroup = 2 },
		"KE length":          func(p *ikev2.IKEPacket) { p.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = []byte{2} },
		"KE zero":            func(p *ikev2.IKEPacket) { p.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = make([]byte, 256) },
		"proposal number":    func(p *ikev2.IKEPacket) { selectedInitProposal(p).ProposalNum = 99 },
		"cross proposal":     func(p *ikev2.IKEPacket) { selectedInitProposal(p).Transforms[0].Attributes[0].Val = 256 },
		"protocol":           func(p *ikev2.IKEPacket) { selectedInitProposal(p).ProtocolID = ikev2.ProtoESP },
		"rekey SPI":          func(p *ikev2.IKEPacket) { selectedInitProposal(p).SPI = make([]byte, 8) },
		"GCM":                func(p *ikev2.IKEPacket) { selectedInitProposal(p).Transforms[0].ID = ikev2.ENCR_AES_GCM_16 },
		"3DES":               func(p *ikev2.IKEPacket) { selectedInitProposal(p).Transforms[0].ID = 3 },
		"XCBC integrity":     func(p *ikev2.IKEPacket) { selectedInitProposal(p).Transforms[1].ID = 5 },
		"weak DH":            func(p *ikev2.IKEPacket) { selectedInitProposal(p).Transforms[3].ID = 2 },
		"duplicate attribute": func(p *ikev2.IKEPacket) {
			xf := selectedInitProposal(p).Transforms[0]
			xf.Attributes = append(xf.Attributes, xf.Attributes[0])
		},
		"duplicate transform": func(p *ikev2.IKEPacket) {
			prop := selectedInitProposal(p)
			prop.Transforms = append(prop.Transforms, prop.Transforms[0])
		},
		"empty proposals": func(p *ikev2.IKEPacket) { p.Payloads[0].(*ikev2.EncryptedPayloadSA).Proposals = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sess, packet := initSelectionFixture(t)
			mutate(packet)
			raw, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			err = sess.handleIKESAInitResp(raw, sess.msgBuffer)
			if err == nil {
				t.Error("accepted invalid selection")
			}
			if sess.SPIr != 0 || sess.Keys != nil || sess.PRFAlg != nil || len(sess.nr) != 0 || sess.fragmentationSupported || sess.natKeepaliveStarted {
				t.Error("invalid response mutated session")
			}
		})
	}
}

func selectedInitProposal(packet *ikev2.IKEPacket) *ikev2.Proposal {
	return packet.Payloads[0].(*ikev2.EncryptedPayloadSA).Proposals[0]
}
