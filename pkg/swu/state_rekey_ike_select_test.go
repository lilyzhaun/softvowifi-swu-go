package swu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func Test_selectIKERekeyResponse_rejectsPRFSwap_whenResponseUsesSHA256(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0)

	_, err := selectEncodedRekey(t, sess, prop, nonce, ke)

	if err == nil {
		t.Fatal("accepted SHA-256 PRF rekey response")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	snap.assertSame(t, sess)
}

func Test_selectIKERekeyResponse_rejectsDHKEMismatch_whenProposal15KE14(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypeDH, ikev2.MODP_3072_bit, 0)
	ke.DHGroup = ikev2.MODP_2048_bit

	_, err := selectEncodedRekey(t, sess, prop, nonce, ke)

	if err == nil {
		t.Fatal("accepted DH15/KE14 rekey response")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	snap.assertSame(t, sess)
}

func Test_selectIKERekeyResponse_rejectsAES256KeyLen_whenCurrentSAIs128(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256)

	_, err := selectEncodedRekey(t, sess, prop, nonce, ke)

	if err == nil {
		t.Fatal("accepted AES-256 rekey response")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	snap.assertSame(t, sess)
}

func Test_selectIKERekeyResponse_rejectsMissingPRF_whenRequiredTransformAbsent(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	prop.Transforms = dropTransform(prop.Transforms, ikev2.TransformTypePRF)

	_, err := selectEncodedRekey(t, sess, prop, nonce, ke)

	if err == nil {
		t.Fatal("accepted rekey response missing PRF")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	snap.assertSame(t, sess)
}

func Test_selectIKERekeyResponse_rejectsDuplicatePRF_whenLastWinnerWouldPass(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	prop.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0)

	_, err := selectEncodedRekey(t, sess, prop, nonce, ke)

	if err == nil {
		t.Fatal("accepted duplicate PRF rekey response")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	snap.assertSame(t, sess)
}

func Test_selectIKERekeyResponse_rejectsShortNonce_whenLength8(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	short := make([]byte, 8)
	short[0] = 0x11
	nonce.NonceData = short

	_, err := selectEncodedRekey(t, sess, prop, nonce, ke)

	if err == nil {
		t.Fatal("accepted 8-byte nonce")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	if strings.Contains(err.Error(), hex.EncodeToString(short)) {
		t.Fatal("nonce bytes leaked in error")
	}
	snap.assertSame(t, sess)
}

type ikeSASnap struct {
	spii, spir uint64
	keys       *ikev2.IKESAKeys
	skd        []byte
	seq        uint32
	dh         *crypto.DiffieHellman
	shared     []byte
	childIn    *ipsec.SecurityAssociation
	childOut   *ipsec.SecurityAssociation
	nat        bool
}

func snapshotIKE(sess *Session) ikeSASnap {
	var shared []byte
	if sess.DH != nil {
		shared = append([]byte(nil), sess.DH.SharedKey...)
	}
	return ikeSASnap{
		spii:     sess.SPIi,
		spir:     sess.SPIr,
		keys:     sess.Keys,
		skd:      append([]byte(nil), sess.Keys.SK_d...),
		seq:      sess.SequenceNumber.Load(),
		dh:       sess.DH,
		shared:   shared,
		childIn:  sess.ChildSAIn,
		childOut: sess.ChildSAOut,
		nat:      sess.natKeepaliveStarted,
	}
}

func (s ikeSASnap) assertSame(t *testing.T, sess *Session) {
	t.Helper()
	if sess.SPIi != s.spii || sess.SPIr != s.spir {
		t.Fatalf("SPI changed to %d/%d", sess.SPIi, sess.SPIr)
	}
	if sess.Keys != s.keys || !bytes.Equal(sess.Keys.SK_d, s.skd) {
		t.Fatal("Keys/SK_d changed")
	}
	if sess.SequenceNumber.Load() != s.seq {
		t.Fatalf("seq = %d, want %d", sess.SequenceNumber.Load(), s.seq)
	}
	if sess.DH != s.dh || !bytes.Equal(sess.DH.SharedKey, s.shared) {
		t.Fatal("DH state changed")
	}
	if sess.ChildSAIn != s.childIn || sess.ChildSAOut != s.childOut {
		t.Fatal("Child SA pointers changed")
	}
	if sess.natKeepaliveStarted != s.nat {
		t.Fatal("NAT keepalive changed")
	}
}

func newRekeySelectFixture(t *testing.T) (*Session, ikeSASnap) {
	t.Helper()
	sess := newLebaraRekeyCryptoSession(t)
	sess.ChildSAIn = &ipsec.SecurityAssociation{SPI: 11}
	sess.ChildSAOut = &ipsec.SecurityAssociation{SPI: 12}
	sess.natKeepaliveStarted = true
	sess.SequenceNumber.Store(7)
	return sess, snapshotIKE(sess)
}

func selectEncodedRekey(t *testing.T, sess *Session, prop *ikev2.Proposal, nonce *ikev2.EncryptedPayloadNonce, ke *ikev2.EncryptedPayloadKE) (ikeRekeySelected, error) {
	t.Helper()
	pkt := encodeRekeyResponse(t, sess,
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{prop}},
		nonce, ke,
	)
	_, payloads, err := sess.decryptAndParse(pkt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return sess.selectIKERekeyResponse(payloads)
}

func lebaraRekeyResponseParts(t *testing.T, sess *Session) (*ikev2.Proposal, *ikev2.EncryptedPayloadKE, *ikev2.EncryptedPayloadNonce) {
	t.Helper()
	peerDH, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatalf("peer DH: %v", err)
	}
	if err := peerDH.GenerateKey(); err != nil {
		t.Fatalf("peer GenerateKey: %v", err)
	}
	spi := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	prop := ikev2.NewProposal(1, ikev2.ProtoIKE, spi)
	prop.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
	prop.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	prop.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_AES128_XCBC, 0)
	prop.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)
	nr := make([]byte, 32)
	nr[0] = 0xAB
	return prop, &ikev2.EncryptedPayloadKE{
		DHGroup: ikev2.MODP_2048_bit,
		KEData:  peerDH.PublicKeyBytes(),
	}, &ikev2.EncryptedPayloadNonce{NonceData: nr}
}

func replaceTransform(src []*ikev2.Transform, typ ikev2.TransformType, id ikev2.AlgorithmType, keyLen int) []*ikev2.Transform {
	out := make([]*ikev2.Transform, len(src))
	copy(out, src)
	for i, xf := range out {
		if xf.Type != typ {
			continue
		}
		next := *xf
		next.ID = id
		next.Attributes = nil
		if keyLen > 0 {
			next.Attributes = []*ikev2.TransformAttribute{{
				Type: ikev2.AttributeKeyLength,
				Val:  uint16(keyLen),
			}}
		}
		out[i] = &next
	}
	return out
}

func dropTransform(src []*ikev2.Transform, typ ikev2.TransformType) []*ikev2.Transform {
	var out []*ikev2.Transform
	for _, xf := range src {
		if xf.Type != typ {
			out = append(out, xf)
		}
	}
	return out
}

func expectedRekeySKd(t *testing.T, oldSKd, dhSecret, ni, nr []byte, spii, spir uint64) []byte {
	t.Helper()
	prf := crypto.PRF_AES128_XCBC
	seed := append(append(append([]byte{}, dhSecret...), ni...), nr...)
	skeyseed, err := prf.Compute(oldSKd, seed)
	if err != nil {
		t.Fatalf("skeyseed: %v", err)
	}
	input := append(append([]byte{}, ni...), nr...)
	spi := make([]byte, 16)
	binary.BigEndian.PutUint64(spi[0:8], spii)
	binary.BigEndian.PutUint64(spi[8:16], spir)
	input = append(input, spi...)
	keyMat, err := crypto.PrfPlus(prf, skeyseed, input, prf.KeyLen())
	if err != nil {
		t.Fatalf("prf+: %v", err)
	}
	return keyMat
}
