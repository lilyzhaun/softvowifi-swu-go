package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

type reauthSnap struct {
	enabled bool
	id      string
	counter uint16
	mk      []byte
	kaut    []byte
	kencr   []byte
	msk     []byte
}

func snapReauth(sess *Session) reauthSnap {
	ctx := sess.fastReauthCtx
	return reauthSnap{
		enabled: ctx.Enabled,
		id:      ctx.ReauthID,
		counter: ctx.Counter,
		mk:      bytes.Clone(ctx.MK),
		kaut:    bytes.Clone(ctx.KAut),
		kencr:   bytes.Clone(ctx.KEncr),
		msk:     bytes.Clone(sess.MSK),
	}
}

func (s reauthSnap) equalCache(other reauthSnap) bool {
	return s.enabled == other.enabled &&
		s.id == other.id &&
		s.counter == other.counter &&
		bytes.Equal(s.mk, other.mk) &&
		bytes.Equal(s.kaut, other.kaut) &&
		bytes.Equal(s.kencr, other.kencr)
}

func type23ReauthSession(t *testing.T, counter uint16, mk, kAut []byte) *Session {
	t.Helper()
	log, _ := diagnosticLogger()
	sess := NewSession(&Config{
		SIM:             issue25ReauthSIM{},
		FastReauthID:    "reauth-synth-id",
		FastReauthMK:    bytes.Clone(mk),
		FastReauthKAut:  bytes.Clone(kAut),
		FastReauthKEncr: bytes.Repeat([]byte{0x44}, 16),
	}, log)
	if sess.fastReauthCtx == nil || !sess.fastReauthCtx.CanUseReauth() {
		t.Fatal("fast reauth cache not populated from Config")
	}
	sess.fastReauthCtx.Counter = counter
	return sess
}

type issue25ReauthSIM struct{}

func (issue25ReauthSIM) GetIMSI() (string, error) { return "001010000000001", nil }
func (issue25ReauthSIM) CalculateAKA(_, _ []byte) ([]byte, []byte, []byte, []byte, error) {
	return bytes.Repeat([]byte{0x60}, 8), bytes.Repeat([]byte{0x43}, 16), bytes.Repeat([]byte{0x49}, 16), nil, nil
}
func (issue25ReauthSIM) Close() error { return nil }

func independentZeroATMAC(raw []byte) []byte {
	tmp := bytes.Clone(raw)
	if len(tmp) < 8 {
		return tmp
	}
	offset := 8
	for offset+2 <= len(tmp) {
		attrLen := int(tmp[offset+1]) * 4
		if attrLen < 4 || offset+attrLen > len(tmp) {
			break
		}
		if tmp[offset] == eap.AT_MAC {
			macStart := offset + 4
			if macStart+16 <= len(tmp) {
				copy(tmp[macStart:macStart+16], make([]byte, 16))
			}
			break
		}
		offset += attrLen
	}
	return tmp
}

func independentType23ReauthRequestMAC(kAut, raw []byte) []byte {
	mac := hmac.New(sha1.New, kAut)
	mac.Write(independentZeroATMAC(raw))
	return mac.Sum(nil)[:16]
}

func independentType23ReauthResponseMAC(kAut, raw, nonceS []byte) []byte {
	mac := hmac.New(sha1.New, kAut)
	mac.Write(independentZeroATMAC(raw))
	mac.Write(nonceS)
	return mac.Sum(nil)[:16]
}

func type23ReauthRequest(id uint8, counter uint16, nonceS, mac []byte, order []uint8) []byte {
	attrs := map[uint8]*eap.Attribute{
		eap.AT_NONCE_S: {Type: eap.AT_NONCE_S, Value: append([]byte{0, 0}, nonceS...)},
		eap.AT_MAC:     {Type: eap.AT_MAC, Value: append([]byte{0, 0}, mac...)},
		eap.AT_COUNTER: {Type: eap.AT_COUNTER, Value: []byte{byte(counter >> 8), byte(counter)}},
	}
	var data []byte
	for _, attrType := range order {
		data = append(data, attrs[attrType].Encode()...)
	}
	return (&eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: id,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeReauthentication,
		Data:       data,
	}).Encode()
}

func signedType23ReauthRequest(id uint8, counter uint16, nonceS, kAut []byte, order []uint8) []byte {
	raw := type23ReauthRequest(id, counter, nonceS, make([]byte, 16), order)
	copyMAC := independentType23ReauthRequestMAC(kAut, raw)
	return type23ReauthRequest(id, counter, nonceS, copyMAC, order)
}

var defaultReauthOrder = []uint8{eap.AT_NONCE_S, eap.AT_MAC, eap.AT_COUNTER}

func Test_handleEAP_Type23Reauth_acceptsValidMAC_whenCachePresent(t *testing.T) {
	// Given
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	sess := type23ReauthSession(t, 20, mk, kAut)
	before := snapReauth(sess)
	raw := signedType23ReauthRequest(7, 30, nonceS, kAut, defaultReauthOrder)

	// When
	payloads, err := sess.handleEAP(raw)

	// Then
	if err != nil || len(payloads) != 1 {
		t.Fatalf("valid Type23 reauth rejected: err=%v n=%d", err, len(payloads))
	}
	wantMSK := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)[32:96]
	if !bytes.Equal(sess.MSK, wantMSK) {
		t.Fatal("MSK differs from independent FIPS186-2 expansion")
	}
	if sess.fastReauthCtx.Counter != 30 || sess.fastReauthCtx.ReauthID != before.id || !sess.fastReauthCtx.Enabled {
		t.Fatal("cache identity/counter not committed on valid reauth")
	}
	resp, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
	if !ok {
		t.Fatal("missing EAP response payload")
	}
	gotMAC := resp.EAPMessage[len(resp.EAPMessage)-16:]
	wantMAC := independentType23ReauthResponseMAC(kAut, resp.EAPMessage, nonceS)
	if !bytes.Equal(gotMAC, wantMAC) {
		t.Fatal("response AT_MAC does not match independent HMAC-SHA1-128 over packet|NONCE_S")
	}
	withoutNonce := hmac.New(sha1.New, kAut)
	withoutNonce.Write(independentZeroATMAC(resp.EAPMessage))
	if bytes.Equal(gotMAC, withoutNonce.Sum(nil)[:16]) {
		t.Fatal("response AT_MAC omitted NONCE_S extra data")
	}
}

func Test_handleEAP_Type23Reauth_rejectsInvalidMAC_whenCachePresent(t *testing.T) {
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	valid := signedType23ReauthRequest(7, 30, nonceS, kAut, defaultReauthOrder)
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1] ^= 0x01
	sha256MAC := hmac.New(sha256.New, bytes.Repeat([]byte{0x99}, 32))
	sha256MAC.Write(independentZeroATMAC(type23ReauthRequest(7, 30, nonceS, make([]byte, 16), defaultReauthOrder)))
	crossFamily := type23ReauthRequest(7, 30, nonceS, sha256MAC.Sum(nil)[:16], defaultReauthOrder)

	cases := []struct {
		name string
		raw  []byte
	}{
		{"missing", (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 7, Type: eap.TypeAKA, Subtype: eap.SubtypeReauthentication, Data: append(
			(&eap.Attribute{Type: eap.AT_NONCE_S, Value: append([]byte{0, 0}, nonceS...)}).Encode(),
			(&eap.Attribute{Type: eap.AT_COUNTER, Value: []byte{0, 30}}).Encode()...,
		)}).Encode()},
		{"zero", type23ReauthRequest(7, 30, nonceS, make([]byte, 16), defaultReauthOrder)},
		{"tampered", tampered},
		{"truncated", (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 7, Type: eap.TypeAKA, Subtype: eap.SubtypeReauthentication, Data: append(append(
			(&eap.Attribute{Type: eap.AT_NONCE_S, Value: append([]byte{0, 0}, nonceS...)}).Encode(),
			(&eap.Attribute{Type: eap.AT_MAC, Value: []byte{0, 0}}).Encode()...),
			(&eap.Attribute{Type: eap.AT_COUNTER, Value: []byte{0, 30}}).Encode()...,
		)}).Encode()},
		{"cross_family_sha256", crossFamily},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := type23ReauthSession(t, 20, mk, kAut)
			before := snapReauth(sess)

			payloads, err := sess.handleEAP(tc.raw)

			if err == nil || len(payloads) != 0 || sess.MSK != nil {
				t.Fatalf("invalid MAC accepted: err=%v n=%d msk=%d", err, len(payloads), len(sess.MSK))
			}
			after := snapReauth(sess)
			if !before.equalCache(after) || after.msk != nil && len(after.msk) != 0 {
				t.Fatal("invalid MAC mutated cache or published MSK")
			}
		})
	}
}

func Test_handleEAP_Type23Reauth_fallsBack_whenMACValidAndCounterTooSmall(t *testing.T) {
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut := bytes.Repeat([]byte{0x22}, 16)
	sess := type23ReauthSession(t, 20, mk, kAut)
	raw := signedType23ReauthRequest(7, 20, bytes.Repeat([]byte{0x33}, 16), kAut, defaultReauthOrder)

	payloads, err := sess.handleEAP(raw)

	if !errors.Is(err, ErrReauth) || len(payloads) != 0 || sess.MSK != nil {
		t.Fatalf("expected full-auth fallback without MSK, err=%v n=%d msk=%d", err, len(payloads), len(sess.MSK))
	}
}

func Test_handleEAP_Type23Reauth_leavesCounterUnchanged_whenMACInvalid(t *testing.T) {
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	sess := type23ReauthSession(t, 20, mk, kAut)
	before := snapReauth(sess)
	raw := type23ReauthRequest(7, 10, nonceS, make([]byte, 16), defaultReauthOrder)

	_, err := sess.handleEAP(raw)

	if err == nil {
		t.Fatal("zero MAC with too-small counter was accepted")
	}
	after := snapReauth(sess)
	if !before.equalCache(after) {
		t.Fatal("MAC failure cleared or altered cache before counter check")
	}
	if sess.MSK != nil {
		t.Fatal("MAC failure published MSK")
	}
}

func Test_handleEAP_Type23Reauth_attributeOrderPermutations_whenMACValid(t *testing.T) {
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x55}, 16)
	orders := [][]uint8{
		{eap.AT_NONCE_S, eap.AT_MAC, eap.AT_COUNTER},
		{eap.AT_NONCE_S, eap.AT_COUNTER, eap.AT_MAC},
		{eap.AT_MAC, eap.AT_NONCE_S, eap.AT_COUNTER},
		{eap.AT_MAC, eap.AT_COUNTER, eap.AT_NONCE_S},
		{eap.AT_COUNTER, eap.AT_NONCE_S, eap.AT_MAC},
		{eap.AT_COUNTER, eap.AT_MAC, eap.AT_NONCE_S},
	}
	wantMSK := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)[32:96]
	for _, order := range orders {
		t.Run(fmt.Sprintf("%d-%d-%d", order[0], order[1], order[2]), func(t *testing.T) {
			sess := type23ReauthSession(t, 4, mk, kAut)
			raw := signedType23ReauthRequest(9, 8, nonceS, kAut, order)

			payloads, err := sess.handleEAP(raw)

			if err != nil || len(payloads) != 1 {
				t.Fatalf("valid permutation rejected: err=%v", err)
			}
			if !bytes.Equal(sess.MSK, wantMSK) || sess.fastReauthCtx.Counter != 8 {
				t.Fatal("permutation changed MSK or counter commit")
			}
			resp := payloads[0].(*ikev2.EncryptedPayloadEAP)
			if !bytes.Equal(resp.EAPMessage[len(resp.EAPMessage)-16:], independentType23ReauthResponseMAC(kAut, resp.EAPMessage, nonceS)) {
				t.Fatal("permutation response MAC missing NONCE_S extra")
			}
		})
	}
}

func Test_handleEAP_Type23Reauth_rejectsInvalidMAC_whenDisableEAPMACValidation(t *testing.T) {
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut := bytes.Repeat([]byte{0x22}, 16)
	log, _ := diagnosticLogger()
	sess := NewSession(&Config{
		SIM:                     issue25ReauthSIM{},
		FastReauthID:            "reauth-synth-id",
		FastReauthMK:            mk,
		FastReauthKAut:          kAut,
		DisableEAPMACValidation: true,
	}, log)
	sess.fastReauthCtx.Counter = 20
	before := snapReauth(sess)
	raw := type23ReauthRequest(7, 30, bytes.Repeat([]byte{0x33}, 16), make([]byte, 16), defaultReauthOrder)

	payloads, err := sess.handleEAP(raw)

	if err == nil || len(payloads) != 0 || sess.MSK != nil {
		t.Fatal("DisableEAPMACValidation bypassed reauth MAC verification")
	}
	if !before.equalCache(snapReauth(sess)) {
		t.Fatal("disabled-flag reject mutated cache")
	}
}

func Test_handleEAP_Type23Reauth_rejectsCrossFamilyKeys_whenType50KAutCached(t *testing.T) {
	mk := bytes.Repeat([]byte{0x11}, 20)
	kAut32 := bytes.Repeat([]byte{0x22}, 32)
	sess := type23ReauthSession(t, 20, mk, kAut32)
	before := snapReauth(sess)
	raw := signedType23ReauthRequest(7, 30, bytes.Repeat([]byte{0x33}, 16), kAut32, defaultReauthOrder)

	payloads, err := sess.handleEAP(raw)

	if err == nil || len(payloads) != 0 || sess.MSK != nil {
		t.Fatal("Type23 reauth accepted Type50-sized K_aut")
	}
	if !before.equalCache(snapReauth(sess)) {
		t.Fatal("cross-family key reject mutated cache")
	}
}

func Test_handleEAP_Type50Reauth_failsClosedWithoutMSK_whenCachePresent(t *testing.T) {
	log, _ := diagnosticLogger()
	mk := bytes.Repeat([]byte{0x11}, 32)
	kAut := bytes.Repeat([]byte{0x22}, 32)
	sess := NewSession(&Config{
		SIM:            issue25ReauthSIM{},
		FastReauthID:   "prime-reauth-id",
		FastReauthMK:   mk,
		FastReauthKAut: kAut,
	}, log)
	sess.fastReauthCtx.Counter = 20
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	raw := (&eap.EAPPacket{
		Code:       eap.CodeRequest,
		Identifier: 7,
		Type:       eap.TypeAKAPrime,
		Subtype:    eap.SubtypeReauthentication,
		Data: append(append(
			(&eap.Attribute{Type: eap.AT_NONCE_S, Value: append([]byte{0, 0}, nonceS...)}).Encode(),
			(&eap.Attribute{Type: eap.AT_MAC, Value: append([]byte{0, 0}, bytes.Repeat([]byte{0xab}, 16)...)}).Encode()...),
			(&eap.Attribute{Type: eap.AT_COUNTER, Value: []byte{0, 30}}).Encode()...,
		),
	}).Encode()

	payloads, err := sess.handleEAP(raw)

	if err == nil || len(payloads) != 0 || len(sess.MSK) != 0 {
		t.Fatalf("Type50 reauth published MSK or succeeded: err=%v n=%d msk=%d", err, len(payloads), len(sess.MSK))
	}
	if !errors.Is(err, ErrReauth) {
		t.Fatalf("Type50 unsupported did not use full-auth fallback signal: %v", err)
	}
}
