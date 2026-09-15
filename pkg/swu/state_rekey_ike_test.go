package swu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func Test_ikeRekeyProposal_usesNegotiatedPRF_whenLebaraXCBC(t *testing.T) {
	// Given Lebara 505003 negotiated suite
	sess := newLebaraRekeySession(t)
	spi := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// When the CREATE_CHILD_SA SA payload is encoded and parsed
	raw, err := (&ikev2.EncryptedPayloadSA{
		Proposals: []*ikev2.Proposal{sess.ikeRekeyProposal(spi)},
	}).Encode()
	if err != nil {
		t.Fatalf("encode SA: %v", err)
	}
	decoded, err := ikev2.DecodePayloadSA(raw)
	if err != nil {
		t.Fatalf("decode SA: %v", err)
	}

	// Then PRF/DH/ENCR match the current SA, not the initial combined grouping
	if len(decoded.Proposals) != 1 {
		t.Fatalf("proposals = %d, want 1", len(decoded.Proposals))
	}
	prop := decoded.Proposals[0]
	if prop.ProtocolID != ikev2.ProtoIKE {
		t.Fatalf("proto = %d, want IKE", prop.ProtocolID)
	}
	if got := transformID(t, prop, ikev2.TransformTypePRF); got != ikev2.PRF_AES128_XCBC {
		t.Fatalf("rekey PRF = %d, want negotiated PRF_AES128_XCBC=%d", got, ikev2.PRF_AES128_XCBC)
	}
	if got := transformID(t, prop, ikev2.TransformTypeDH); got != ikev2.MODP_2048_bit {
		t.Fatalf("rekey DH = %d, want 14", got)
	}
	if got := transformID(t, prop, ikev2.TransformTypeEncr); got != ikev2.ENCR_AES_CBC {
		t.Fatalf("rekey ENCR = %d, want AES-CBC", got)
	}
}

func Test_ikeRekeyProposal_encodesDHFromCurrentSA_whenNotGroup14Hardcode(t *testing.T) {
	// Given a current SA whose DH is not the layout default 14
	sess := newLebaraRekeySession(t)
	sess.ikeDHID = uint16(ikev2.MODP_3072_bit)

	// When
	raw, err := (&ikev2.EncryptedPayloadSA{
		Proposals: []*ikev2.Proposal{sess.ikeRekeyProposal(make([]byte, 8))},
	}).Encode()
	if err != nil {
		t.Fatalf("encode SA: %v", err)
	}
	decoded, err := ikev2.DecodePayloadSA(raw)
	if err != nil {
		t.Fatalf("decode SA: %v", err)
	}

	// Then
	got := transformID(t, decoded.Proposals[0], ikev2.TransformTypeDH)
	if got != ikev2.MODP_3072_bit {
		t.Fatalf("rekey DH = %d, want current SA group 15", got)
	}
}

func Test_handleRekeyIKESAResp_rejectsNO_PROPOSAL_CHOSEN(t *testing.T) {
	// Given an encrypted CREATE_CHILD_SA response with error notify 14
	sess := newLebaraRekeyCryptoSession(t)
	pkt := encodeRekeyResponse(t, sess, &ikev2.EncryptedPayloadNotify{
		NotifyType: ikev2.NO_PROPOSAL_CHOSEN,
	})

	// When
	err := sess.handleRekeyIKESAResp(pkt, []byte("ni"), sess.DH, 9, sess.Keys.SK_d, sess.SPIi, sess.SPIr)

	// Then
	var typed *ikeRekeyError
	if err == nil || !errors.As(err, &typed) || typed.notifyType != 14 {
		t.Fatalf("err = %v, want notify 14", err)
	}
}

func Test_handleRekeyIKESAResp_rejectsPRFSwap_whenResponseUsesSHA256(t *testing.T) {
	sess, snap := newRekeySelectFixture(t)
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0)
	ni := make([]byte, 32)
	ni[0] = 0xCD

	err := sess.handleRekeyIKESAResp(encodeRekeyResponse(t, sess,
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{prop}},
		nonce, ke,
	), ni, sess.DH, 0x1111111111111111, sess.Keys.SK_d, sess.SPIi, sess.SPIr)

	if err == nil {
		t.Fatal("accepted SHA-256 PRF rekey response")
	}
	if !errors.Is(err, errIKERekeyResponse) {
		t.Fatalf("err = %v, want %v", err, errIKERekeyResponse)
	}
	snap.assertSame(t, sess)
}

func Test_handleRekeyIKESAResp_replacesSKdAndSeq0_whenValidXCBCResponse(t *testing.T) {
	sess := newLebaraRekeyCryptoSession(t)
	childIn := &ipsec.SecurityAssociation{SPI: 21}
	childOut := &ipsec.SecurityAssociation{SPI: 22}
	sess.ChildSAIn = childIn
	sess.ChildSAOut = childOut
	sess.natKeepaliveStarted = true
	sess.SequenceNumber.Store(7)
	oldSKd := append([]byte(nil), sess.Keys.SK_d...)
	oldSPIi, oldSPIr := sess.SPIi, sess.SPIr
	prop, ke, nonce := lebaraRekeyResponseParts(t, sess)
	newSPIi := uint64(0x2222222222222222)
	ni := make([]byte, 32)
	ni[0] = 0xCD
	newSPIr := binary.BigEndian.Uint64(prop.SPI)

	if err := sess.handleRekeyIKESAResp(encodeRekeyResponse(t, sess,
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{prop}},
		nonce, ke,
	), ni, sess.DH, newSPIi, oldSKd, oldSPIi, oldSPIr); err != nil {
		t.Fatalf("handleRekeyIKESAResp: %v", err)
	}

	if sess.SequenceNumber.Load() != 0 {
		t.Fatalf("seq = %d, want 0", sess.SequenceNumber.Load())
	}
	if bytes.Equal(sess.Keys.SK_d, oldSKd) {
		t.Fatal("SK_d not replaced")
	}
	wantSKd := expectedRekeySKd(t, oldSKd, sess.DH.SharedKey, ni, nonce.NonceData, newSPIi, newSPIr)
	if !bytes.Equal(sess.Keys.SK_d, wantSKd) {
		t.Fatalf("SK_d = %s, want XCBC %s", hex.EncodeToString(sess.Keys.SK_d), hex.EncodeToString(wantSKd))
	}
	if sess.SPIi != newSPIi || sess.SPIr != newSPIr {
		t.Fatalf("IKE SPI = %d/%d, want %d/%d", sess.SPIi, sess.SPIr, newSPIi, newSPIr)
	}
	if sess.ChildSAIn != childIn || sess.ChildSAOut != childOut {
		t.Fatal("Child SA pointers changed")
	}
	if !sess.natKeepaliveStarted {
		t.Fatal("NAT keepalive cleared")
	}
}

func Test_handleRekeyIKESAResp_preservesChildSAAndNAT_whenValidResponse(t *testing.T) {
	// Given established Lebara IKE + Child SA + NAT-T
	sess := newLebaraRekeyCryptoSession(t)
	childIn := &ipsec.SecurityAssociation{SPI: 11}
	childOut := &ipsec.SecurityAssociation{SPI: 12}
	sess.ChildSAIn = childIn
	sess.ChildSAOut = childOut
	sess.natKeepaliveStarted = true
	oldSPIi, oldSPIr := sess.SPIi, sess.SPIr

	peerDH, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatalf("peer DH: %v", err)
	}
	if err := peerDH.GenerateKey(); err != nil {
		t.Fatalf("peer GenerateKey: %v", err)
	}
	newSPIrBytes := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	newSPIr := binary.BigEndian.Uint64(newSPIrBytes)
	respProp := ikev2.NewProposal(1, ikev2.ProtoIKE, newSPIrBytes)
	respProp.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
	respProp.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	respProp.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_AES128_XCBC, 0)
	respProp.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)
	nr := make([]byte, 32)
	nr[0] = 0xAB
	pkt := encodeRekeyResponse(t, sess,
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{respProp}},
		&ikev2.EncryptedPayloadNonce{NonceData: nr},
		&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_2048_bit, KEData: peerDH.PublicKeyBytes()},
	)
	newSPIi := uint64(0x1111111111111111)
	ni := make([]byte, 32)
	ni[0] = 0xCD

	// When
	if err := sess.handleRekeyIKESAResp(pkt, ni, sess.DH, newSPIi, sess.Keys.SK_d, oldSPIi, oldSPIr); err != nil {
		t.Fatalf("handleRekeyIKESAResp: %v", err)
	}

	// Then IKE SPI migrated and Child/NAT state is unchanged
	if sess.SPIi != newSPIi || sess.SPIr != newSPIr {
		t.Fatalf("IKE SPI = %d/%d, want %d/%d", sess.SPIi, sess.SPIr, newSPIi, newSPIr)
	}
	if sess.ChildSAIn != childIn || sess.ChildSAOut != childOut {
		t.Fatal("Child SA pointers changed during IKE rekey")
	}
	if !sess.natKeepaliveStarted {
		t.Fatal("NAT keepalive cleared during IKE rekey")
	}
}

func newLebaraRekeySession(t *testing.T) *Session {
	t.Helper()
	sess := NewSession(&Config{
		EpDGAddr:  "192.0.2.2",
		EpDGPort:  500,
		LocalAddr: "192.0.2.1",
		LocalPort: 4500,
	}, zap.NewNop())
	sess.ikeEncrID = uint16(ikev2.ENCR_AES_CBC)
	sess.ikeIntegID = uint16(ikev2.AUTH_HMAC_SHA2_256_128)
	sess.ikePRFID = uint16(ikev2.PRF_AES128_XCBC)
	sess.ikeDHID = uint16(ikev2.MODP_2048_bit)
	sess.ikeEncrKeyLenBits = 128
	return sess
}

func newLebaraRekeyCryptoSession(t *testing.T) *Session {
	t.Helper()
	sess := newLebaraRekeySession(t)
	enc, err := crypto.GetEncrypterWithKeyLen(uint16(ikev2.ENCR_AES_CBC), 128)
	if err != nil {
		t.Fatalf("encrypter: %v", err)
	}
	integ, err := crypto.GetIntegrityAlgorithm(uint16(ikev2.AUTH_HMAC_SHA2_256_128))
	if err != nil {
		t.Fatalf("integ: %v", err)
	}
	prf, err := crypto.GetPRF(uint16(ikev2.PRF_AES128_XCBC))
	if err != nil {
		t.Fatalf("prf: %v", err)
	}
	sess.EncAlg = enc
	sess.IntegAlg = integ
	sess.PRFAlg = prf
	key := make([]byte, enc.KeySize())
	integKey := make([]byte, integ.KeySize())
	skd := make([]byte, prf.KeyLen())
	skd[0] = 0x42
	sess.Keys = &ikev2.IKESAKeys{
		SK_d:  skd,
		SK_ei: key,
		SK_er: key,
		SK_ai: integKey,
		SK_ar: integKey,
	}
	sess.SPIi = 1
	sess.SPIr = 2
	dh, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatalf("DH: %v", err)
	}
	if err := dh.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sess.DH = dh
	return sess
}

func encodeRekeyResponse(t *testing.T, sess *Session, payloads ...ikev2.Payload) []byte {
	t.Helper()
	raw, err := sess.encryptAndWrapWithMsgID(payloads, ikev2.CREATE_CHILD_SA, 1, true)
	if err != nil {
		t.Fatalf("encrypt response: %v", err)
	}
	return raw
}

func transformID(t *testing.T, prop *ikev2.Proposal, typ ikev2.TransformType) ikev2.AlgorithmType {
	t.Helper()
	for _, xf := range prop.Transforms {
		if xf.Type == typ {
			return xf.ID
		}
	}
	t.Fatalf("missing transform type %d", typ)
	return 0
}
