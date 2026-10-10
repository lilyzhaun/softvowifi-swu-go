package swu

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// Extend the historical synthetic golden independently of the production
// builder. Preserve its five offers and every other payload byte.
func withSHA512Offer(t *testing.T, legacy []byte) []byte {
	t.Helper()
	for kind, offset := byte(35), 0; kind != 0; {
		if offset+4 > len(legacy) {
			t.Fatal("truncated golden payload")
		}
		size := int(binary.BigEndian.Uint16(legacy[offset+2 : offset+4]))
		if size < 4 || offset+size > len(legacy) {
			t.Fatal("invalid golden payload size")
		}
		if kind == 33 {
			last := offset + 4
			for n := 1; n < 5; n++ {
				last += int(binary.BigEndian.Uint16(legacy[last+2 : last+4]))
			}
			if last+40 != offset+size || !bytes.Equal(legacy[last:last+8], []byte{0, 0, 0, 40, 5, 3, 4, 3}) {
				t.Fatal("golden must end in legacy ESP offer five")
			}
			added := referenceHex(t, "0000002806030403123456780300000c0100000c800e0100030000080300000e0000000805000000")
			copy(added[8:12], legacy[last+8:last+12])
			out := append(bytes.Clone(legacy[:offset+size]), added...)
			out = append(out, legacy[offset+size:]...)
			out[last] = 2
			binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(size+len(added)))
			return out
		}
		kind, offset = legacy[offset], offset+size
	}
	t.Fatal("golden has no SA payload")
	return nil
}

func TestAUTH1OffersCompleteAES256SHA512ESP(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	payloads, err := sess.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sess.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		t.Fatal(err)
	}
	_, decoded, err := testPeerReceiver(sess).decryptAndParse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var proposals []*ikev2.Proposal
	for _, payload := range decoded {
		if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			proposals = sa.Proposals
		}
	}
	if len(proposals) != 6 {
		t.Fatalf("want five preserved offers plus AES256/SHA512, got %d", len(proposals))
	}
	// Independent numeric contract: RFC 4868 SHA2-512-256 is integrity ID 14.
	want := [][3]int{{20, 256, 0}, {20, 128, 0}, {12, 256, 12}, {12, 128, 12}, {12, 128, 2}, {12, 256, 14}}
	for i, proposal := range proposals {
		if proposal.ProposalNum != uint8(i+1) || proposal.ProtocolID != 3 || !bytes.Equal(proposal.SPI, []byte{10, 11, 12, 13}) {
			t.Fatalf("proposal %d changed its protocol, number or SPI", i)
		}
		var got [3]int
		esn := false
		for _, tr := range proposal.Transforms {
			switch tr.Type {
			case 1:
				got[0] = int(tr.ID)
				if len(tr.Attributes) != 1 || tr.Attributes[0].Type != 14 {
					t.Fatal("missing explicit AES key length")
				}
				got[1] = int(tr.Attributes[0].Val)
			case 3:
				got[2] = int(tr.ID)
			case 5:
				esn = tr.ID == 0
			default:
				t.Fatal("unexpected PRF/DH in initial ESP offer")
			}
		}
		if got != want[i] || !esn {
			t.Fatalf("proposal %d: got %v no-esn=%v", i, got, esn)
		}
	}
}

func TestFinalAUTHInstallsOfferedAES256SHA512ESP(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	p := ikev2.NewProposal(6, ikev2.ProtoESP, []byte{0x22, 0x22, 0x22, 0x22})
	p.AddTransform(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256)
	p.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_512_256, 0)
	p.AddTransform(ikev2.TransformTypeESN, 0, 0)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), validResponderAUTH(t, sess), &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{p}}}))
	if err != nil {
		t.Fatal(err)
	}
	if sess.childEncrID != 12 || sess.childEncrKeyLenBits != 256 || sess.childIntegID != 14 || sess.childESN {
		t.Fatal("wrong negotiated ESP suite")
	}
	if len(sess.ChildSAIn.EncryptionKey) != 32 || len(sess.ChildSAOut.EncryptionKey) != 32 || len(sess.ChildSAIn.IntegrityKey) != 64 || len(sess.ChildSAOut.IntegrityKey) != 64 {
		t.Fatal("wrong RFC 4868 ESP key lengths")
	}
}
