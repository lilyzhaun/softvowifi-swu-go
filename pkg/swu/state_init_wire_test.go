package swu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func Test_InitAcceptsOnlySentProposal_whenConfigurationChanges(t *testing.T) {
	for index := 0; index < 4; index++ {
		t.Run(string(rune('1'+index)), func(t *testing.T) {
			sess, packet := initSelectionFixture(t)
			offered := bytes.Clone(sess.msgBuffer)
			sa, _, _ := decodeInitSA(t, offered)
			if len(sa.Proposals) != 4 {
				t.Fatalf("wire proposals = %d", len(sa.Proposals))
			}
			packet.Payloads[0] = &ikev2.EncryptedPayloadSA{Proposals: sa.Proposals[index : index+1]}
			sess.cfg.IKEProposalLayout = ikev2.ProposalLayoutSingleCombined
			raw, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.handleIKESAInitResp(raw, offered); err != nil {
				t.Fatal(err)
			}
			if sess.Keys == nil || sess.ikeDHID != 14 {
				t.Fatal("no negotiated keys")
			}
		})
	}
}

func Test_InitCookieRetryKeepsOffer_whenNotifyOnly(t *testing.T) {
	sess, packet := initSelectionFixture(t)
	before, _, _ := decodeInitSA(t, sess.msgBuffer)
	want, err := before.Encode()
	if err != nil {
		t.Fatal(err)
	}
	packet.Header.SPIr = 0
	packet.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: bytes.Repeat([]byte{5}, 64)}}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.handleIKESAInitResp(raw, sess.msgBuffer); !errors.Is(err, ErrCookieRequired) {
		t.Fatalf("cookie: %v", err)
	}
	if sess.SPIr != 0 || sess.Keys != nil {
		t.Fatal("cookie changed SA")
	}
	retry, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	after, _, _ := decodeInitSA(t, retry)
	got, err := after.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || len(retry) >= 1232 {
		t.Fatalf("changed offer or oversized retry: %d", len(retry))
	}
	t.Logf("encoded COOKIE retry: %d bytes", len(retry))
}

func Test_InitRejectsMalformedWire_whenDecoderCouldRetainPartialPayload(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"short generic header":  func(raw []byte) []byte { binary.BigEndian.PutUint16(raw[30:32], 3); return raw },
		"hidden transforms":     func(raw []byte) []byte { raw[39] = 3; return raw },
		"trailing bytes":        func(raw []byte) []byte { return append(raw, 0) },
		"truncated":             func(raw []byte) []byte { return raw[:len(raw)-1] },
		"dangling next payload": func(raw []byte) []byte { raw[len(raw)-36] = byte(ikev2.N); return raw },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sess, packet := initSelectionFixture(t)
			raw, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.handleIKESAInitResp(mutate(raw), sess.msgBuffer); err == nil {
				t.Fatal("accepted malformed wire")
			}
			if sess.SPIr != 0 || sess.Keys != nil || sess.PRFAlg != nil || len(sess.nr) != 0 {
				t.Fatal("malformed wire changed state")
			}
		})
	}
}

func Test_InitRejectsCookie_whenHeaderDoesNotMatch(t *testing.T) {
	sess, packet := initSelectionFixture(t)
	packet.Header.SPIi++
	packet.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{5}}}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.handleIKESAInitResp(raw, sess.msgBuffer); err == nil || errors.Is(err, ErrCookieRequired) {
		t.Fatalf("wrong cookie result: %v", err)
	}
	if sess.sendCookie || len(sess.cookie) != 0 {
		t.Fatal("unbound cookie saved")
	}
}

func Test_CombinedProposalPreservesWire_whenDefaultPolicyExpanded(t *testing.T) {
	want, err := hex.DecodeString("000000600101000a0300000c0100000c800e00800300000c0100000c800e0100030000080300000c030000080300000d03000008030000020300000802000005030000080200000603000008020000020300000802000004000000080400000e")
	if err != nil {
		t.Fatal(err)
	}
	sa := &ikev2.EncryptedPayloadSA{Proposals: ikev2.CreateCombinedProposalIKE(nil)}
	got, err := sa.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("combined changed: %x", got)
	}
}

func Test_InitXCBCSelectionRequiresCombinedOffer_whenPRFSelected(t *testing.T) {
	for _, layout := range []string{"", ikev2.ProposalLayoutSingleCombined} {
		t.Run(layout, func(t *testing.T) {
			sess, packet := initSelectionFixture(t)
			sess.cfg.IKEProposalLayout = layout
			offered, err := sess.buildIKESAInitPacket()
			if err != nil {
				t.Fatal(err)
			}
			selectedInitProposal(packet).Transforms[2].ID = ikev2.PRF_AES128_XCBC
			raw, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			err = sess.handleIKESAInitResp(raw, offered)
			if layout == ikev2.ProposalLayoutSingleCombined {
				if err != nil || sess.Keys == nil || sess.ikePRFID != uint16(ikev2.PRF_AES128_XCBC) {
					t.Fatalf("combined XCBC: %v", err)
				}
			} else if !errors.Is(err, ikev2.ErrInitResponse) || sess.Keys != nil || sess.SPIr != 0 {
				t.Fatalf("unoffered XCBC: %v", err)
			}
		})
	}
}
