package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/sim"
)

// Public RFC5448 Appendix C cases 1–4, not subscriber material. Independent
// reference expansion is checked against every published output, not itself.
type primeStandardVector struct{ network, rand, autn, ck, ik, res, prime, material string }

var primeStandardVectors = []primeStandardVector{
	{"WLAN", "81e92b6c0ee0e12ebceba8d92a99dfa5", "bb52e91c747ac3ab2a5c23d15ee351d5", "5349fbe098649f948f5d2e973a81c00f", "9744871ad32bf9bbd1dd5ce54e3e2e5a", "28d7b0f2a2ec3de5",
		"0093962d0dd84aa5684b045c9edffa04ccfc230ca74fcc96c0a5d61164f5a76c",
		"766fa0a6c317174b812d52fbcd11a1790842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71eacf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75af861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"},
	{"HRPD", "81e92b6c0ee0e12ebceba8d92a99dfa5", "bb52e91c747ac3ab2a5c23d15ee351d5", "5349fbe098649f948f5d2e973a81c00f", "9744871ad32bf9bbd1dd5ce54e3e2e5a", "28d7b0f2a2ec3de5",
		"3820f0277fa5f77732b1fb1d90c1a0dadb94a0ab557ef6c9ab48619ca05b9a9f",
		"05ad73ac915fce89ac77e1520d82187b5b4acaef62c6ebb8882b2f3d534c4b35277337a00184f20ff25d224c04be2afd3f90bf5c6e5ef325ff04eb5ef6539fa8cca8398194fbd00be425b3f40dba10ac87b321570117cd6c95ab6c436fb5073ff15cf85505d2bc5bb7355fc21ea8a75757e8f86a2b138002e05752913bb43b82f868a96117e91a2d95f526677d572900c891d5f20f148a1007553e2dea555c9cb672e9675f4a66b4bafa027379f93aee539a5979d0a0042b9d2ae28bed3b17a31dc8ab75072b80bd0c1da612466e402c"},
	{"WLAN", "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0", "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
		"cd4c8e5c68f57dd1d7d7dfd0c538e5773ece6b705dbbf7dfc459a11280c65524",
		"897d302fa2847416488c28e20dcb7be4c40700e7722483ae3dc7139eb0b88bb558cb3081eccd057f9207d1286ee7dd530a591a22dd8b5b1cf29e3d508c91dbbdb4aee23051892c42b6a2de66ea5044739f7dca9e37bb22029ed986e7cd09d4a70d1ac76d95535c5cac40a7504699bb8961a29ef6f3e90f183de5861ad1bedc81ce9916391b401aa006c98785a5756df7724de00bdb9e568187be3fe746114557d5018779537ee37f4d3c6c738cb97b9dc651bc19bfadc344ffe2b52ca78bd8316b51dacc5f2b1440cb9515521cc7ba23"},
	{"HRPD", "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0", "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
		"8310a71ce6f754889613da8f64d5fb465adf14360ae838192db23f6fcb7f8c76",
		"745e7439ba238f50fcac4d15d47cd1d93e1d2aa4e677025cfd862a4be18361a13a645765571463df833a9759e809987999da835e2ae82462576fe6516fad1f802f0fa1191655dd0a273da96d04e0fcd3c6d3a6e0ceea951eb20d74f32c3061d0680a04b0b086ee8700ace3e0b95fa02683c287beee44432294ff98af26d2cc783bace75c4b0af7fdfeb5511ba8e4cbd07fb56813838adafa99d140c2f198f6dacebfb6afee444961105402b508c7f363352cb2919644b50463e6a69354150147ae09cbc54b8a651d8787a6893ed8536d"},
}

const primePublicIdentity = "0555444333222111"

func primeIndependentMaterial(ck, ik, autn, identity []byte, network string) ([]byte, []byte) {
	input := append([]byte{0x20}, []byte(network)...)
	input = binary.BigEndian.AppendUint16(input, uint16(len(network)))
	input = append(input, autn[:6]...)
	input = append(input, 0, 6)
	m := hmac.New(sha256.New, append(bytes.Clone(ck), ik...))
	m.Write(input)
	prime := m.Sum(nil)
	key := append(bytes.Clone(prime[16:]), prime[:16]...)
	seed := append([]byte("EAP-AKA'"), identity...)
	var out, last []byte
	for n := byte(1); len(out) < 208; n++ {
		m = hmac.New(sha256.New, key)
		m.Write(last)
		m.Write(seed)
		m.Write([]byte{n})
		last = m.Sum(nil)
		out = append(out, last...)
	}
	return prime, out[:208]
}

func primeStandardRequest(t *testing.T, v primeStandardVector, result bool, kdfs ...uint16) []byte {
	t.Helper()
	raw := []byte{1, 0x93, 0, 0, 50, 1, 0, 0, 1, 5, 0, 0}
	raw = append(raw, referenceHex(t, v.rand)...)
	raw = append(raw, 2, 5, 0, 0)
	raw = append(raw, referenceHex(t, v.autn)...)
	name := []byte(v.network)
	size := (4 + len(name) + 3) / 4
	raw = append(raw, 23, byte(size), byte(len(name)>>8), byte(len(name)))
	raw = append(raw, name...)
	raw = append(raw, make([]byte, size*4-4-len(name))...)
	for _, kdf := range kdfs {
		raw = append(raw, 24, 1, byte(kdf>>8), byte(kdf))
	}
	if result {
		raw = append(raw, 135, 1, 0, 0)
	}
	raw = append(raw, 11, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	key := referenceHex(t, v.material)[16:48]
	m := hmac.New(sha256.New, key)
	m.Write(raw)
	copy(raw[len(raw)-16:], m.Sum(nil)[:16])
	return raw
}

func primeStandardSession(t *testing.T, v primeStandardVector) (*Session, *vectorSIM) {
	t.Helper()
	p := &vectorSIM{res: referenceHex(t, v.res), ck: referenceHex(t, v.ck), ik: referenceHex(t, v.ik)}
	s := NewSession(&Config{SIM: p}, nil)
	s.akaIdentity.outer = []byte(primePublicIdentity)
	return s, p
}

func primeExpectedResponse(t *testing.T, v primeStandardVector, result bool) []byte {
	t.Helper()
	res := referenceHex(t, v.res)
	length := (4 + len(res) + 3) / 4
	raw := []byte{2, 0x93, 0, 0, 50, 1, 0, 0, 3, byte(length), 0, byte(len(res) * 8)}
	raw = append(raw, res...)
	raw = append(raw, make([]byte, 4*length-4-len(res))...)
	if result {
		raw = append(raw, 135, 1, 0, 0)
	}
	raw = append(raw, 11, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	m := hmac.New(sha256.New, referenceHex(t, v.material)[16:48])
	m.Write(raw)
	copy(raw[len(raw)-16:], m.Sum(nil)[:16])
	return raw
}

func TestPrimeRFC5448PublishedVectorsAndIndependentWire(t *testing.T) {
	for index, v := range primeStandardVectors {
		t.Run(fmt.Sprintf("case%d", index+1), func(t *testing.T) {
			prime, material := primeIndependentMaterial(referenceHex(t, v.ck), referenceHex(t, v.ik), referenceHex(t, v.autn), []byte(primePublicIdentity), v.network)
			if !bytes.Equal(prime, referenceHex(t, v.prime)) || !bytes.Equal(material, referenceHex(t, v.material)) {
				t.Fatal("independent reference does not match public RFC5448 vector")
			}
			for _, result := range []bool{false, true} {
				s, p := primeStandardSession(t, v)
				raw := primeStandardRequest(t, v, result, 1)
				before := bytes.Clone(raw)
				pls, err := s.handleEAP(raw)
				if err != nil || len(pls) != 1 {
					t.Fatalf("published standard Challenge was rejected: %v", err)
				}
				if !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, primeExpectedResponse(t, v, result)) || !bytes.Equal(s.MSK, material[80:144]) || !bytes.Equal(s.eapKAut, material[16:48]) || p.calls != 1 || !bytes.Equal(raw, before) {
					t.Fatal("public vector key slices/response/MAC/input ownership or SIM count differs")
				}
			}
		})
	}
}

func TestPrimeMandatoryInputRejectedBeforeSIM(t *testing.T) {
	for _, variant := range []string{"missing actual identity", "missing KDF", "missing network", "missing RAND", "missing AUTN", "missing MAC", "empty network", "bad network length", "invalid UTF8", "AMF clear", "short RAND", "bad KDF length", "duplicate MAC", "duplicate RAND", "duplicate KDF value", "unknown mandatory", "trailing byte"} {
		t.Run(variant, func(t *testing.T) {
			v := primeStandardVectors[0]
			s, p := primeStandardSession(t, v)
			if variant == "missing actual identity" {
				s.akaIdentity.outer = nil
			}
			raw := primeStandardRequest(t, v, false, 1)
			var filtered []byte
			for offset := 8; offset < len(raw); {
				length := int(raw[offset+1]) * 4
				attr := bytes.Clone(raw[offset : offset+length])
				kind := attr[0]
				if (variant == "missing KDF" && kind == 24) || (variant == "missing network" && kind == 23) || (variant == "missing RAND" && kind == 1) || (variant == "missing AUTN" && kind == 2) || (variant == "missing MAC" && kind == 11) {
					offset += length
					continue
				}
				if kind == 23 {
					switch variant {
					case "empty network":
						attr[2], attr[3] = 0, 0
					case "bad network length":
						attr[3] = 255
					case "invalid UTF8":
						attr[4] = 255
					}
				}
				if kind == 2 && variant == "AMF clear" {
					attr[10] &= 0x7f
				}
				if kind == 1 && variant == "short RAND" {
					attr = attr[:16]
					attr[1] = 4
				}
				if kind == 24 && variant == "bad KDF length" {
					attr = append(attr, 0, 0, 0, 0)
					attr[1] = 2
				}
				filtered = append(filtered, attr...)
				if (kind == 11 && variant == "duplicate MAC") || (kind == 1 && variant == "duplicate RAND") || (kind == 24 && variant == "duplicate KDF value") {
					filtered = append(filtered, attr...)
				}
				offset += length
			}
			raw = append(raw[:8:8], filtered...)
			if variant == "unknown mandatory" {
				raw = append(raw, 99, 1, 0, 0)
			}
			binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			if variant == "trailing byte" {
				raw = append(raw, 0)
			}
			if _, err := s.handleEAP(raw); err == nil || p.calls != 0 || len(s.MSK) != 0 || len(s.eapKAut) != 0 {
				t.Fatal("invalid mandatory/structural input accessed SIM or committed keys")
			}
		})
	}
}

func TestPrimeMACAndIdentityFailuresNeverCommitOrDiscloseValues(t *testing.T) {
	for _, variant := range []string{"bad MAC", "wrong identity", "bypass flag"} {
		s, p := primeStandardSession(t, primeStandardVectors[0])
		raw := primeStandardRequest(t, primeStandardVectors[0], false, 1)
		if variant == "wrong identity" {
			s.akaIdentity.outer = []byte("different-public-identity")
		} else {
			raw[len(raw)-1] ^= 1
		}
		if variant == "bypass flag" {
			s.cfg.DisableEAPMACValidation = true
		}
		_, err := s.handleEAP(raw)
		if err == nil || p.calls != 1 || len(s.MSK) != 0 || len(s.eapKAut) != 0 {
			t.Fatal("bad MAC/identity or bypass committed Prime method")
		}
		if bytes.Contains([]byte(err.Error()), []byte("calc=")) || bytes.Contains([]byte(err.Error()), []byte("recv=")) {
			t.Fatal("Prime error includes method MAC material")
		}
	}
}

func TestPrimeKDFNegotiationPreservesOrderedServerOffer(t *testing.T) {
	v := primeStandardVectors[0]
	s, p := primeStandardSession(t, v)
	pls, err := s.handleEAP(primeStandardRequest(t, v, false, 2, 1))
	if err != nil || len(pls) != 1 || !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, []byte{2, 0x93, 0, 12, 50, 1, 0, 0, 24, 1, 0, 1}) || p.calls != 0 {
		t.Fatal("KDF selection did not answer only selected alternative before SIM")
	}
	if _, err := s.handleEAP(primeStandardRequest(t, v, false, 2, 1)); err != nil || p.calls != 0 {
		t.Fatal("negotiation retransmission accessed SIM or failed")
	}
	pls, err = s.handleEAP(primeStandardRequest(t, v, false, 1, 2, 1))
	if err != nil || p.calls != 1 || !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, primeExpectedResponse(t, v, false)) {
		t.Fatal("legitimate selected-first duplicate offer did not complete standard Challenge")
	}
	pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage[0] ^= 1
	pls, err = s.handleEAP(primeStandardRequest(t, v, false, 1, 2, 1))
	if err != nil || p.calls != 1 || !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, primeExpectedResponse(t, v, false)) {
		t.Fatal("completed negotiated Challenge retransmission repeated SIM or returned aliased response")
	}
	s, p = primeStandardSession(t, v)
	if _, err := s.handleEAP(primeStandardRequest(t, v, false, 2, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleEAP(primeStandardRequest(t, v, false, 1, 3, 1)); err == nil || p.calls != 0 {
		t.Fatal("server changed more than requested KDF list")
	}
	s.resetAKAIdentity()
	if _, err := s.handleEAP(primeStandardRequest(t, v, false, 1, 2, 1)); err == nil {
		t.Fatal("old negotiated duplicate list survived reset")
	}
}

func TestPrimeProductionDerivationMatchesAllPublishedKeySlices(t *testing.T) {
	for _, v := range primeStandardVectors {
		ck, ik := referenceHex(t, v.ck), referenceHex(t, v.ik)
		beforeCK, beforeIK := bytes.Clone(ck), bytes.Clone(ik)
		material, err := deriveAKAPrime(ck, ik, referenceHex(t, v.autn), []byte(primePublicIdentity), v.network)
		if err != nil || !bytes.Equal(material, referenceHex(t, v.material)) || !bytes.Equal(ck, beforeCK) || !bytes.Equal(ik, beforeIK) {
			t.Fatal("production keys differ from a public vector or overwrite SIM material")
		}
	}
}

type primeSyncSIM struct {
	vectorSIM
	auts []byte
}

func (p *primeSyncSIM) CalculateAKA(_, _ []byte) ([]byte, []byte, []byte, []byte, error) {
	p.calls++
	return nil, nil, nil, bytes.Clone(p.auts), sim.ErrSyncFailure
}

func TestPrimeSyncResponseRetainsMethodAndNegotiatedKDFList(t *testing.T) {
	v := primeStandardVectors[0]
	s, _ := primeStandardSession(t, v)
	p := &primeSyncSIM{auts: bytes.Repeat([]byte{0x53}, 14)}
	s.cfg.SIM = p
	if _, err := s.handleEAP(primeStandardRequest(t, v, false, 2, 1)); err != nil {
		t.Fatal(err)
	}
	pls, err := s.handleEAP(primeStandardRequest(t, v, false, 1, 2, 1))
	want := []byte{2, 0x93, 0, 36, 50, 4, 0, 0, 4, 4}
	want = append(want, p.auts...)
	want = append(want, 24, 1, 0, 1, 24, 1, 0, 2, 24, 1, 0, 1)
	if err != nil || !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, want) || p.calls != 1 || len(s.MSK) != 0 || s.eapNotification.authenticated {
		t.Fatal("sync failure lost Type50 or last KDF list, or authenticated without keys")
	}
	provider := &vectorSIM{res: referenceHex(t, v.res), ck: referenceHex(t, v.ck), ik: referenceHex(t, v.ik)}
	s.cfg.SIM = provider
	raw := primeStandardRequest(t, v, false, 1, 2, 1)
	raw[1] = 0x94
	clear(raw[len(raw)-16:])
	m := hmac.New(sha256.New, referenceHex(t, v.material)[16:48])
	m.Write(raw)
	copy(raw[len(raw)-16:], m.Sum(nil)[:16])
	if _, err := s.handleEAP(raw); err != nil || provider.calls != 1 {
		t.Fatal("post-sync Challenge rejected its unchanged previously negotiated KDF list")
	}
}

func TestPrimeNegotiationCannotFallBackToAKAMethod(t *testing.T) {
	v := primeStandardVectors[0]
	s, p := primeStandardSession(t, v)
	if _, err := s.handleEAP(primeStandardRequest(t, v, false, 2, 1)); err != nil {
		t.Fatal(err)
	}
	akaKey := referenceAKAKeys(p, false)[16:32]
	if _, err := s.handleEAP(referenceChallenge(akaKey, false)); err == nil || p.calls != 0 {
		t.Fatal("Prime KDF negotiation silently changed to AKA")
	}
}
