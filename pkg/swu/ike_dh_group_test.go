package swu

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

const rfc2409Group2PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

func setConfigIKEDHGroup(t *testing.T, cfg *Config, group uint16) {
	t.Helper()
	val := reflect.ValueOf(cfg).Elem().FieldByName("IKEDHGroup")
	if !val.IsValid() || !val.CanSet() || val.Kind() != reflect.Uint16 {
		t.Fatalf("Config missing settable uint16 IKEDHGroup field")
	}
	val.SetUint(uint64(group))
}

func independentGroup2KeyPair(t *testing.T, fill byte) (*big.Int, *big.Int, []byte) {
	t.Helper()
	p, ok := new(big.Int).SetString(rfc2409Group2PrimeHex, 16)
	if !ok {
		t.Fatal("invalid RFC 2409 prime")
	}
	priv := new(big.Int).SetBytes(bytes.Repeat([]byte{fill, fill ^ 0x5a}, 60))
	pub := new(big.Int).Exp(big.NewInt(2), priv, p).FillBytes(make([]byte, 128))
	return p, priv, pub
}

func independentIKEKeys(newHash func() hash.Hash, prfLen int, secret, ni, nr []byte, spii, spir uint64, totalLen int) []byte {
	nonces := append(bytes.Clone(ni), nr...)
	mac := hmac.New(newHash, nonces)
	mac.Write(secret)
	skeyseed := mac.Sum(nil)

	input := append(bytes.Clone(nonces), binary.BigEndian.AppendUint64(nil, spii)...)
	input = binary.BigEndian.AppendUint64(input, spir)

	var prev, out []byte
	for counter := byte(1); len(out) < totalLen; counter++ {
		h := hmac.New(newHash, skeyseed)
		h.Write(prev)
		h.Write(input)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:totalLen]
}

func TestIKEDHGroupDefaultPreservedAndInvalidGroupsRejected(t *testing.T) {
	for _, group := range []uint16{0, 14} {
		sess := newInitTestSession("")
		if group != 0 {
			setConfigIKEDHGroup(t, sess.cfg, group)
		}
		raw, err := sess.buildIKESAInitPacket()
		if err != nil {
			t.Fatalf("buildIKESAInitPacket(group=%d): %v", group, err)
		}
		sa, ke, _ := decodeInitSA(t, raw)
		if ke.DHGroup != ikev2.MODP_2048_bit || len(ke.KEData) != 256 {
			t.Fatalf("group=%d KE: group=%d len=%d, want 14/256", group, ke.DHGroup, len(ke.KEData))
		}
		baseline, err := (&ikev2.EncryptedPayloadSA{Proposals: ikev2.CreateIKEProposals("", nil)}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		gotSA, err := sa.Encode()
		if err != nil || !bytes.Equal(gotSA, baseline) {
			t.Fatalf("group=%d altered default SA proposals", group)
		}
	}

	for _, invalid := range []uint16{1, 5, 15, 16, 19, 20, 21, 99} {
		sess := newInitTestSession("")
		sess.cfg.IKEDHGroup = invalid
		if _, err := sess.buildIKESAInitPacket(); err == nil {
			t.Fatalf("buildIKESAInitPacket accepted unsupported IKEDHGroup=%d", invalid)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		sessConn := NewSession(&Config{
			EpDGAddr:   "127.0.0.1",
			EpDGPort:   500,
			LocalAddr:  "127.0.0.1",
			LocalPort:  0,
			IKEDHGroup: invalid,
		}, zap.NewNop())
		err := sessConn.Connect(ctx)
		cancel()
		sessConn.Shutdown()
		if err == nil {
			t.Fatalf("Connect accepted unsupported IKEDHGroup=%d", invalid)
		}
	}

	// Unauthenticated Notify 14 or INVALID_KE_PAYLOAD(2) must never auto-downgrade a group 14 session.
	sess := newInitTestSession("")
	offered, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	for _, rawNotify := range [][]byte{
		initHintWire(sess.SPIi, ikev2.NO_PROPOSAL_CHOSEN, nil),
		initHintWire(sess.SPIi, ikev2.INVALID_KE_PAYLOAD, []byte{0, 2}),
	} {
		_ = sess.handleIKESAInitResp(rawNotify, offered)
		again, err := sess.buildIKESAInitPacket()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, offered) || sess.DH.Group != 14 {
			t.Fatal("unauthenticated error notify downgraded or mutated the offered DH group")
		}
	}
}

func TestIKEDHGroup2InitCookieAndKeyDerivation(t *testing.T) {
	// 1. Multiple-complete and single-combined layouts with explicit group 2.
	for _, layout := range []string{"", ikev2.ProposalLayoutMultipleComplete, ikev2.ProposalLayoutSingleCombined} {
		sess := newInitTestSession(layout)
		setConfigIKEDHGroup(t, sess.cfg, 2)
		raw, err := sess.buildIKESAInitPacket()
		if err != nil {
			t.Fatalf("layout=%q buildIKESAInitPacket(group=2): %v", layout, err)
		}
		sa, ke, _ := decodeInitSA(t, raw)
		if ke.DHGroup != ikev2.MODP_1024_bit || len(ke.KEData) != 128 {
			t.Fatalf("layout=%q KE group=%d len=%d, want 2/128", layout, ke.DHGroup, len(ke.KEData))
		}
		baseProposals := ikev2.CreateIKEProposals(layout, nil)
		if len(sa.Proposals) != len(baseProposals) {
			t.Fatalf("layout=%q proposals=%d, want %d", layout, len(sa.Proposals), len(baseProposals))
		}
		for i, prop := range sa.Proposals {
			base := baseProposals[i]
			if prop.ProposalNum != base.ProposalNum || len(prop.Transforms) != len(base.Transforms) {
				t.Fatalf("layout=%q proposal %d structure changed", layout, i)
			}
			for j, xf := range prop.Transforms {
				bxf := base.Transforms[j]
				if xf.Type != bxf.Type {
					t.Fatalf("layout=%q proposal %d transform %d type=%d, want %d", layout, i, j, xf.Type, bxf.Type)
				}
				if xf.Type == ikev2.TransformTypeDH {
					if xf.ID != ikev2.MODP_1024_bit {
						t.Fatalf("layout=%q proposal %d DH=%d, want 2", layout, i, xf.ID)
					}
				} else if xf.ID != bxf.ID || len(xf.Attributes) != len(bxf.Attributes) {
					t.Fatalf("layout=%q proposal %d transform %d non-DH changed", layout, i, j)
				}
			}
		}

		// COOKIE challenge must preserve original DH2, KE and SA offer even if cfg is mutated afterwards.
		cookieBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
		cookieResp := ikev2.NewIKEPacket()
		cookieResp.Header.SPIi = sess.SPIi
		cookieResp.Header.Version = 0x20
		cookieResp.Header.ExchangeType = ikev2.IKE_SA_INIT
		cookieResp.Header.Flags = ikev2.FlagResponse
		cookieResp.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: cookieBytes}}
		cookieRaw, err := cookieResp.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.handleIKESAInitResp(cookieRaw, raw); !errors.Is(err, ErrCookieRequired) {
			t.Fatalf("expected ErrCookieRequired, got %v", err)
		}
		setConfigIKEDHGroup(t, sess.cfg, 14)
		sess.cfg.InitialIKEProposalNumber = 4
		retry, err := sess.buildIKESAInitPacket()
		if err != nil {
			t.Fatal(err)
		}
		cookiePayloadLen := 8 + len(cookieBytes)
		if retry[16] != byte(ikev2.N) || !bytes.Equal(retry[28+cookiePayloadLen:], raw[28:]) {
			t.Fatalf("layout=%q COOKIE retry did not preserve original DH2 offer/KE bytes", layout)
		}
	}

	// 2. End-to-end IKE_SA_INIT response validation and key derivation with independent math/big peer.
	sess := newInitTestSession("")
	setConfigIKEDHGroup(t, sess.cfg, 2)
	offered, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	sa, ke, _ := decodeInitSA(t, offered)
	p, peerPriv, peerPub := independentGroup2KeyPair(t, 0x41)
	indepSecret := new(big.Int).Exp(new(big.Int).SetBytes(ke.KEData), peerPriv, p).FillBytes(make([]byte, 128))

	nr := bytes.Repeat([]byte{0x7b}, 32)
	resp := ikev2.NewIKEPacket()
	resp.Header = &ikev2.IKEHeader{
		SPIi:         sess.SPIi,
		SPIr:         0x0102030405060708,
		Version:      0x20,
		ExchangeType: ikev2.IKE_SA_INIT,
		Flags:        ikev2.FlagResponse,
	}
	// Select proposal 3 (AES-CBC-128 + HMAC-SHA1-96 + PRF-HMAC-SHA1 + MODP_1024).
	resp.Payloads = []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sa.Proposals[2]}},
		&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: peerPub},
		&ikev2.EncryptedPayloadNonce{NonceData: nr},
	}
	respRaw, err := resp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.handleIKESAInitResp(respRaw, offered); err != nil {
		t.Fatalf("handleIKESAInitResp(DH2 proposal 3) failed: %v", err)
	}
	if sess.ikeDHID != 2 || sess.DH == nil || sess.DH.Group != 2 || !bytes.Equal(sess.DH.SharedKey, indepSecret) {
		t.Fatalf("negotiated DH2 state mismatch: ikeDHID=%d", sess.ikeDHID)
	}

	// PRF_HMAC_SHA1 (20B) * 3 + AUTH_HMAC_SHA1_96 (20B) * 2 + ENCR_AES_CBC_128 (16B) * 2 = 132 bytes.
	wantMat := independentIKEKeys(sha1.New, 20, indepSecret, sess.ni, nr, sess.SPIi, sess.SPIr, 132)
	if !bytes.Equal(sess.Keys.SK_d, wantMat[0:20]) ||
		!bytes.Equal(sess.Keys.SK_ai, wantMat[20:40]) ||
		!bytes.Equal(sess.Keys.SK_ar, wantMat[40:60]) ||
		!bytes.Equal(sess.Keys.SK_ei, wantMat[60:76]) ||
		!bytes.Equal(sess.Keys.SK_er, wantMat[76:92]) ||
		!bytes.Equal(sess.Keys.SK_pi, wantMat[92:112]) ||
		!bytes.Equal(sess.Keys.SK_pr, wantMat[112:132]) {
		t.Fatal("derived IKE SA keys do not match independent SHA1/DH2 key material")
	}
}

func TestValidateInitSelectionDynamicDHGroupAndStrictRejections(t *testing.T) {
	p1024, _, validPub2 := independentGroup2KeyPair(t, 0x52)
	dh14, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatal(err)
	}
	if err := dh14.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	validPub14 := dh14.PublicKeyBytes()

	// When group 14 was offered, a response selecting group 2 (even though group 2 is supported) must be rejected.
	sess14 := newInitTestSession("")
	offered14, err := sess14.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	sa14, _, _ := decodeInitSA(t, offered14)
	prop2On14 := *sa14.Proposals[0]
	prop2On14.Transforms = replaceTransform(prop2On14.Transforms, ikev2.TransformTypeDH, ikev2.MODP_1024_bit, 0)
	resp2On14 := ikev2.NewIKEPacket()
	resp2On14.Header = &ikev2.IKEHeader{SPIi: sess14.SPIi, SPIr: 1234, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
	resp2On14.Payloads = []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&prop2On14}},
		&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: validPub2},
		&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{9}, 32)},
	}
	raw2On14, err := resp2On14.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess14.handleIKESAInitResp(raw2On14, offered14); !errors.Is(err, ikev2.ErrInitResponse) {
		t.Fatalf("group 14 session accepted unoffered group 2 response: %v", err)
	}

	// When group 2 was offered, reject unoffered group 14, wrong KE lengths, bad KE values, wrong proposal number and cross-proposal hybrid.
	pMinusOne2 := new(big.Int).Sub(p1024, big.NewInt(1)).FillBytes(make([]byte, 128))
	one2 := make([]byte, 128)
	one2[127] = 1

	cases := map[string]func(*ikev2.IKEPacket){
		"unoffered_group14": func(pkt *ikev2.IKEPacket) {
			prop := selectedInitProposal(pkt)
			prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)
			pkt.Payloads[1] = &ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_2048_bit, KEData: validPub14}
		},
		"ke_group14_with_sa_group2": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1] = &ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_2048_bit, KEData: validPub14}
		},
		"sa_group14_with_ke_group2": func(pkt *ikev2.IKEPacket) {
			prop := selectedInitProposal(pkt)
			prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)
		},
		"ke_len_256_for_group2": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = validPub14
		},
		"ke_len_127_for_group2": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = validPub2[:127]
		},
		"ke_len_129_for_group2": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = append(bytes.Clone(validPub2), 1)
		},
		"ke_zero": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = make([]byte, 128)
		},
		"ke_one": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = one2
		},
		"ke_p_minus_one": func(pkt *ikev2.IKEPacket) {
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = pMinusOne2
		},
		"unknown_proposal_num": func(pkt *ikev2.IKEPacket) {
			selectedInitProposal(pkt).ProposalNum = 99
		},
		"cross_proposal_hybrid": func(pkt *ikev2.IKEPacket) {
			prop := selectedInitProposal(pkt)
			prop.Transforms = replaceTransform(prop.Transforms, ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA1, 0)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sess2 := newInitTestSession("")
			setConfigIKEDHGroup(t, sess2.cfg, 2)
			offered2, err := sess2.buildIKESAInitPacket()
			if err != nil {
				t.Fatal(err)
			}
			sa2, _, _ := decodeInitSA(t, offered2)
			chosen := *sa2.Proposals[0]
			chosen.Transforms = append([]*ikev2.Transform(nil), chosen.Transforms...)
			pkt := ikev2.NewIKEPacket()
			pkt.Header = &ikev2.IKEHeader{SPIi: sess2.SPIi, SPIr: 5678, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
			pkt.Payloads = []ikev2.Payload{
				&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&chosen}},
				&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: bytes.Clone(validPub2)},
				&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{7}, 32)},
			}
			mutate(pkt)
			raw, err := pkt.Encode()
			if err != nil {
				t.Fatal(err)
			}
			err = sess2.handleIKESAInitResp(raw, offered2)
			var numHint *ikev2.InitProposalNumberError
			if !errors.Is(err, ikev2.ErrInitResponse) || errors.As(err, &numHint) {
				t.Fatalf("case %q expected plain ErrInitResponse without number hint, got %v", name, err)
			}
			if sess2.Keys != nil || sess2.SPIr != 0 {
				t.Fatalf("case %q mutated session state", name)
			}
		})
	}
}

func TestIKEDHGroup2RenumberedThirdProposalHintAndNarrowedRetry(t *testing.T) {
	_, _, peerPub2 := independentGroup2KeyPair(t, 0x63)

	// Step 1: 4 complete DH2 offers sent; network chooses suite #3 but renumbers it to #1.
	sess := newInitTestSession("")
	setConfigIKEDHGroup(t, sess.cfg, 2)
	offered, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	sa, _, _ := decodeInitSA(t, offered)
	if len(sa.Proposals) != 4 {
		t.Fatalf("offered proposals = %d, want 4", len(sa.Proposals))
	}
	renumbered := *sa.Proposals[2] // Original proposal 3: AES-CBC-128 + SHA1 + PRF-SHA1 + DH2
	renumbered.ProposalNum = 1

	resp := ikev2.NewIKEPacket()
	resp.Header = &ikev2.IKEHeader{SPIi: sess.SPIi, SPIr: 0x9988776655443322, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
	resp.Payloads = []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&renumbered}},
		&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: peerPub2},
		&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x44}, 32)},
	}
	rawResp, err := resp.Encode()
	if err != nil {
		t.Fatal(err)
	}

	err = sess.handleIKESAInitResp(rawResp, offered)
	if !errors.Is(err, ikev2.ErrInitResponse) || !strings.Contains(err.Error(), "proposal number mismatch (offered 3)") {
		t.Fatalf("expected rejected proposal number mismatch (offered 3), got %v", err)
	}
	var hint *ikev2.InitProposalNumberError
	if !errors.As(err, &hint) || hint.OfferedNumber != 3 {
		t.Fatalf("expected InitProposalNumberError{OfferedNumber: 3}, got %v", err)
	}
	if sess.Keys != nil || sess.SPIr != 0 {
		t.Fatal("renumbered DH2 response must not be accepted directly")
	}

	// Step 2: Fresh session narrowed to InitialIKEProposalNumber=3 with IKEDHGroup=2.
	fresh := newInitTestSession("")
	setConfigIKEDHGroup(t, fresh.cfg, 2)
	fresh.cfg.InitialIKEProposalNumber = 3
	narrowedOffer, err := fresh.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	narrowedSA, narrowedKE, _ := decodeInitSA(t, narrowedOffer)
	if len(narrowedSA.Proposals) != 1 || narrowedSA.Proposals[0].ProposalNum != 1 || narrowedKE.DHGroup != ikev2.MODP_1024_bit || len(narrowedKE.KEData) != 128 {
		t.Fatalf("unexpected narrowed DH2 offer: proposals=%d keGroup=%d keLen=%d", len(narrowedSA.Proposals), narrowedKE.DHGroup, len(narrowedKE.KEData))
	}
	wantNarrowedBytes, err := (&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&renumbered}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	gotNarrowedBytes, err := narrowedSA.Encode()
	if err != nil || !bytes.Equal(gotNarrowedBytes, wantNarrowedBytes) {
		t.Fatal("narrowed DH2 proposal #3 bytes do not match original proposal #3 renumbered to 1")
	}

	resp.Header.SPIi = fresh.SPIi
	rawFreshResp, err := resp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.handleIKESAInitResp(rawFreshResp, narrowedOffer); err != nil {
		t.Fatalf("narrowed DH2 session rejected valid response: %v", err)
	}
	if fresh.Keys == nil || fresh.ikeDHID != 2 || fresh.ikePRFID != uint16(ikev2.PRF_HMAC_SHA1) {
		t.Fatalf("narrowed DH2 session state mismatch: keys=%v dh=%d prf=%d", fresh.Keys != nil, fresh.ikeDHID, fresh.ikePRFID)
	}
}

func newDH2RekeyCryptoSession(t *testing.T) *Session {
	t.Helper()
	sess := NewSession(&Config{
		EpDGAddr:  "192.0.2.2",
		EpDGPort:  500,
		LocalAddr: "192.0.2.1",
		LocalPort: 4500,
	}, zap.NewNop())
	setConfigIKEDHGroup(t, sess.cfg, 2)
	sess.ikeEncrID = uint16(ikev2.ENCR_AES_CBC)
	sess.ikeIntegID = uint16(ikev2.AUTH_HMAC_SHA2_256_128)
	sess.ikePRFID = uint16(ikev2.PRF_HMAC_SHA2_256)
	sess.ikeDHID = uint16(ikev2.MODP_1024_bit)
	sess.ikeEncrKeyLenBits = 128

	enc, err := crypto.GetEncrypterWithKeyLen(sess.ikeEncrID, sess.ikeEncrKeyLenBits)
	if err != nil {
		t.Fatal(err)
	}
	integ, err := crypto.GetIntegrityAlgorithm(sess.ikeIntegID)
	if err != nil {
		t.Fatal(err)
	}
	prf, err := crypto.GetPRF(sess.ikePRFID)
	if err != nil {
		t.Fatal(err)
	}
	sess.EncAlg = enc
	sess.IntegAlg = integ
	sess.PRFAlg = prf
	sess.Keys = &ikev2.IKESAKeys{
		SK_d:  bytes.Repeat([]byte{0x11}, prf.KeyLen()),
		SK_ei: bytes.Repeat([]byte{0x22}, enc.KeySize()),
		SK_er: bytes.Repeat([]byte{0x33}, enc.KeySize()),
		SK_ai: bytes.Repeat([]byte{0x44}, integ.KeySize()),
		SK_ar: bytes.Repeat([]byte{0x55}, integ.KeySize()),
	}
	sess.SPIi = 0x1111222233334444
	sess.SPIr = 0x5555666677778888
	dh, err := crypto.NewDiffieHellman(2)
	if err != nil {
		t.Fatalf("NewDiffieHellman(2): %v", err)
	}
	if err := dh.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	sess.DH = dh
	return sess
}

func TestIKEDHGroup2BidirectionalRekey(t *testing.T) {
	p1024, peerPriv, peerPub := independentGroup2KeyPair(t, 0x74)

	// Part 1: Local-initiated RekeyIKESA over DH2.
	t.Run("local_initiated", func(t *testing.T) {
		sess := newDH2RekeyCryptoSession(t)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		sess.ctx, sess.cancel = ctx, cancel
		pipe := &pipeTransport{sent: make(chan []byte, 8)}
		sess.socket = pipe
		sess.taskMgr = NewTaskManager(ctx, nil, 1, func(pkts [][]byte) error {
			for _, pkt := range pkts {
				if err := pipe.SendIKE(pkt); err != nil {
					return err
				}
			}
			return nil
		})
		defer sess.taskMgr.Stop()

		oldSKd := bytes.Clone(sess.Keys.SK_d)
		errCh := make(chan error, 1)
		go func() { errCh <- sess.RekeyIKESA() }()

		reqWire := <-pipe.sent
		reqHdr, err := ikev2.DecodeHeader(reqWire)
		if err != nil {
			t.Fatal(err)
		}
		_, reqPayloads, err := testPeerReceiver(sess).decryptAndParse(reqWire)
		if err != nil {
			t.Fatalf("decrypt local rekey request: %v", err)
		}
		var reqSA *ikev2.EncryptedPayloadSA
		var reqNonce *ikev2.EncryptedPayloadNonce
		var reqKE *ikev2.EncryptedPayloadKE
		for _, pl := range reqPayloads {
			switch v := pl.(type) {
			case *ikev2.EncryptedPayloadSA:
				reqSA = v
			case *ikev2.EncryptedPayloadNonce:
				reqNonce = v
			case *ikev2.EncryptedPayloadKE:
				reqKE = v
			}
		}
		if reqSA == nil || reqNonce == nil || reqKE == nil {
			t.Fatal("missing SA/Nonce/KE in local DH2 rekey request")
		}
		if reqKE.DHGroup != ikev2.MODP_1024_bit || len(reqKE.KEData) != 128 {
			t.Fatalf("local rekey KE group=%d len=%d, want 2/128", reqKE.DHGroup, len(reqKE.KEData))
		}
		if gotDH := transformID(t, reqSA.Proposals[0], ikev2.TransformTypeDH); gotDH != ikev2.MODP_1024_bit {
			t.Fatalf("local rekey SA DH=%d, want 2", gotDH)
		}

		// Reject wrong KE length or wrong DH group before accepting valid response.
		newSPIrBytes := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}
		newSPIr := binary.BigEndian.Uint64(newSPIrBytes)
		respProp := sess.ikeRekeyProposal(newSPIrBytes)
		nr := bytes.Repeat([]byte{0x9c}, 32)
		badLenResp := encodePeerPacket(t, sess, []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{respProp}},
			&ikev2.EncryptedPayloadNonce{NonceData: nr},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: make([]byte, 256)},
		}, ikev2.CREATE_CHILD_SA, reqHdr.MessageID, true)
		if err := sess.handleRekeyIKESAResp(badLenResp, reqNonce.NonceData, sess.DH, binary.BigEndian.Uint64(reqSA.Proposals[0].SPI), oldSKd, sess.SPIi, sess.SPIr); err == nil {
			t.Fatal("accepted 256-byte KE in DH2 local rekey response")
		}

		// Valid DH2 response + old SA DELETE ack.
		validResp := encodePeerPacket(t, sess, []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{respProp}},
			&ikev2.EncryptedPayloadNonce{NonceData: nr},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: peerPub},
		}, ikev2.CREATE_CHILD_SA, reqHdr.MessageID, true)
		if !sess.taskMgr.HandleResponse(reqHdr.MessageID, validResp) {
			t.Fatal("taskMgr rejected valid rekey response")
		}

		delWire := <-pipe.sent
		delHdr, err := ikev2.DecodeHeader(delWire)
		if err != nil {
			t.Fatal(err)
		}
		delAck := encodePeerPacket(t, sess, nil, ikev2.INFORMATIONAL, delHdr.MessageID, true)
		sess.taskMgr.HandleResponse(delHdr.MessageID, delAck)

		if err := <-errCh; err != nil {
			t.Fatalf("RekeyIKESA(DH2) failed: %v", err)
		}
		if sess.DH == nil || sess.DH.Group != 2 || len(sess.DH.SharedKey) != 128 {
			t.Fatalf("post-rekey DH mismatch: %+v", sess.DH)
		}
		indepSecret := new(big.Int).Exp(new(big.Int).SetBytes(reqKE.KEData), peerPriv, p1024).FillBytes(make([]byte, 128))
		mac := hmac.New(sha256.New, oldSKd)
		mac.Write(indepSecret)
		mac.Write(reqNonce.NonceData)
		mac.Write(nr)
		skeyseed := mac.Sum(nil)
		newSPIi := binary.BigEndian.Uint64(reqSA.Proposals[0].SPI)
		input := append(append(bytes.Clone(reqNonce.NonceData), nr...), binary.BigEndian.AppendUint64(nil, newSPIi)...)
		input = binary.BigEndian.AppendUint64(input, newSPIr)
		h1 := hmac.New(sha256.New, skeyseed)
		h1.Write(input)
		h1.Write([]byte{1})
		wantSKd := h1.Sum(nil)
		if !bytes.Equal(sess.Keys.SK_d, wantSKd) {
			t.Fatal("local DH2 rekey SK_d does not match independent RFC 7296 §2.18 derivation")
		}
	})

	// Part 2: Peer-initiated HandleRekeyIKESARequest over DH2.
	t.Run("peer_initiated", func(t *testing.T) {
		sess := newDH2RekeyCryptoSession(t)
		pipe := &pipeTransport{sent: make(chan []byte, 8)}
		sess.socket = pipe
		oldKeys := sess.Keys
		oldSKd := bytes.Clone(sess.Keys.SK_d)

		// 2a. Peer sends wrong DH group (14 when session is 2) -> rejected with INVALID_KE_PAYLOAD(2).
		dh14, err := crypto.NewDiffieHellman(14)
		if err != nil {
			t.Fatal(err)
		}
		if err := dh14.GenerateKey(); err != nil {
			t.Fatal(err)
		}
		wrongGroupPayloads := []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sess.ikeRekeyProposal([]byte{1, 2, 3, 4, 5, 6, 7, 8})}},
			&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x5a}, 32)},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_2048_bit, KEData: dh14.PublicKeyBytes()},
		}
		if err := sess.HandleRekeyIKESARequest(0, wrongGroupPayloads); err == nil {
			t.Fatal("accepted peer rekey with wrong DH group 14")
		}
		rejectWire := <-pipe.sent
		_, rejectPayloads, err := testPeerReceiver(sess).decryptAndParse(rejectWire)
		if err != nil || len(rejectPayloads) != 1 {
			t.Fatalf("decrypt INVALID_KE rejection: %v", err)
		}
		n, ok := rejectPayloads[0].(*ikev2.EncryptedPayloadNotify)
		if !ok || n.NotifyType != ikev2.INVALID_KE_PAYLOAD || !bytes.Equal(n.NotifyData, []byte{0, 2}) {
			t.Fatalf("expected INVALID_KE_PAYLOAD with group 2, got %+v", n)
		}
		if sess.Keys != oldKeys {
			t.Fatal("rejected peer rekey mutated session keys")
		}

		// 2b. Peer sends DH2 but wrong KE length (256B) -> rejected without committing.
		wrongLenPayloads := []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sess.ikeRekeyProposal([]byte{1, 2, 3, 4, 5, 6, 7, 8})}},
			&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x5a}, 32)},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: make([]byte, 256)},
		}
		if err := sess.HandleRekeyIKESARequest(0, wrongLenPayloads); err == nil {
			t.Fatal("accepted peer rekey with 256-byte KE for group 2")
		}
		select {
		case <-pipe.sent:
		default:
		}
		if sess.Keys != oldKeys {
			t.Fatal("rejected peer rekey mutated session keys")
		}

		// 2c. Peer sends valid DH2 proposal and 128-byte public key.
		peerSPIBytes := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
		peerSPI := binary.BigEndian.Uint64(peerSPIBytes)
		ni := bytes.Repeat([]byte{0x5a}, 32)
		validPeerPayloads := []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sess.ikeRekeyProposal(peerSPIBytes)}},
			&ikev2.EncryptedPayloadNonce{NonceData: ni},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: peerPub},
		}
		oldReceiver := testPeerReceiver(sess)
		if err := sess.HandleRekeyIKESARequest(0, validPeerPayloads); err != nil {
			t.Fatalf("HandleRekeyIKESARequest(DH2) failed: %v", err)
		}
		replyWire := <-pipe.sent
		_, replyPayloads, err := oldReceiver.decryptAndParse(replyWire)
		if err != nil {
			t.Fatalf("decrypt peer rekey response: %v", err)
		}
		var respSA *ikev2.EncryptedPayloadSA
		var respNonce *ikev2.EncryptedPayloadNonce
		var respKE *ikev2.EncryptedPayloadKE
		for _, pl := range replyPayloads {
			switch v := pl.(type) {
			case *ikev2.EncryptedPayloadSA:
				respSA = v
			case *ikev2.EncryptedPayloadNonce:
				respNonce = v
			case *ikev2.EncryptedPayloadKE:
				respKE = v
			}
		}
		if respSA == nil || respNonce == nil || respKE == nil || respKE.DHGroup != ikev2.MODP_1024_bit || len(respKE.KEData) != 128 {
			t.Fatalf("invalid DH2 peer rekey response payloads: ke=%+v", respKE)
		}
		if !sess.localResponder || sess.DH == nil || sess.DH.Group != 2 || sess.SPIi != peerSPI {
			t.Fatal("peer DH2 rekey did not commit responder role and group 2 DH")
		}
		indepSecret := new(big.Int).Exp(new(big.Int).SetBytes(respKE.KEData), peerPriv, p1024).FillBytes(make([]byte, 128))
		mac := hmac.New(sha256.New, oldSKd)
		mac.Write(indepSecret)
		mac.Write(ni)
		mac.Write(respNonce.NonceData)
		skeyseed := mac.Sum(nil)
		input := append(append(bytes.Clone(ni), respNonce.NonceData...), binary.BigEndian.AppendUint64(nil, peerSPI)...)
		input = binary.BigEndian.AppendUint64(input, sess.SPIr)
		h1 := hmac.New(sha256.New, skeyseed)
		h1.Write(input)
		h1.Write([]byte{1})
		if !bytes.Equal(sess.Keys.SK_d, h1.Sum(nil)) {
			t.Fatal("peer DH2 rekey SK_d does not match independent derivation")
		}
	})
}

func TestConnectUDPWithExplicitIKEDHGroup2(t *testing.T) {
	p1024, peerPriv, peerPub := independentGroup2KeyPair(t, 0x85)

	// Subtest 1: 4 offers in DH2 where peer renumbers offer #3 to #1 -> strict failure with OfferedNumber=3.
	t.Run("renumbered_third_offer_hint", func(t *testing.T) {
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(4 * time.Second))

		sess := newInitTestSession("")
		setConfigIKEDHGroup(t, sess.cfg, 2)
		sess.cfg.LocalAddr, sess.cfg.LocalPort = "127.0.0.1", 0
		sess.cfg.EpDGAddr, sess.cfg.EpDGPort = "127.0.0.1", uint16(peer.LocalAddr().(*net.UDPAddr).Port)

		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- sess.Connect(ctx) }()
		t.Cleanup(func() { cancel(); sess.Shutdown() })

		buf := make([]byte, 4096)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		sa, ke, _ := decodeInitSA(t, buf[:n])
		if len(sa.Proposals) != 4 || ke.DHGroup != ikev2.MODP_1024_bit || len(ke.KEData) != 128 {
			t.Fatalf("unexpected wire offer: proposals=%d keGroup=%d keLen=%d", len(sa.Proposals), ke.DHGroup, len(ke.KEData))
		}
		reqPkt, err := ikev2.DecodePacket(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		chosen := *sa.Proposals[2]
		chosen.ProposalNum = 1
		resp := ikev2.NewIKEPacket()
		resp.Header = &ikev2.IKEHeader{SPIi: reqPkt.Header.SPIi, SPIr: 9876, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
		resp.Payloads = []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&chosen}},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: peerPub},
			&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x33}, 32)},
		}
		raw, err := resp.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(raw, addr); err != nil {
			t.Fatal(err)
		}

		err = <-done
		var hint *ikev2.InitProposalNumberError
		if !errors.Is(err, ikev2.ErrInitResponse) || !errors.As(err, &hint) || hint.OfferedNumber != 3 {
			t.Fatalf("Connect with renumbered DH2 offer #3 returned %v, want OfferedNumber=3", err)
		}
	})

	// Subtest 2: Narrowed offer #3 with DH2 + COOKIE challenge -> completes IKE_SA_INIT and sends encrypted IKE_AUTH.
	t.Run("cookie_then_narrowed_third_suite_to_protected_auth", func(t *testing.T) {
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(4 * time.Second))

		sess := newInitTestSession("")
		setConfigIKEDHGroup(t, sess.cfg, 2)
		sess.cfg.InitialIKEProposalNumber = 3
		sess.cfg.LocalAddr, sess.cfg.LocalPort = "127.0.0.1", 0
		sess.cfg.EpDGAddr, sess.cfg.EpDGPort = "127.0.0.1", uint16(peer.LocalAddr().(*net.UDPAddr).Port)
		sess.cfg.FastReauthID = "synthetic@invalid"

		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- sess.Connect(ctx) }()
		t.Cleanup(func() { cancel(); sess.Shutdown() })

		buf := make([]byte, 4096)
		// 1st packet: initial IKE_SA_INIT without COOKIE.
		n1, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		firstOffer := bytes.Clone(buf[:n1])
		req1, err := ikev2.DecodePacket(firstOffer)
		if err != nil {
			t.Fatal(err)
		}
		cookieResp := ikev2.NewIKEPacket()
		cookieResp.Header = &ikev2.IKEHeader{SPIi: req1.Header.SPIi, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
		cookieResp.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{0xca, 0xfe, 0xba, 0xbe}}}
		cookieWire, err := cookieResp.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(cookieWire, addr); err != nil {
			t.Fatal(err)
		}

		// 2nd packet: COOKIE retry preserving narrowed DH2 offer and KE.
		n2, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		retryOffer := bytes.Clone(buf[:n2])
		if !bytes.Equal(retryOffer[28+12:], firstOffer[28:]) {
			t.Fatal("UDP COOKIE retry altered narrowed DH2 offer or KE")
		}
		req2, err := ikev2.DecodePacket(retryOffer)
		if err != nil {
			t.Fatal(err)
		}
		sa2, ke2, _ := decodeInitSA(t, retryOffer)
		var ni []byte
		for _, pl := range req2.Payloads {
			if nonce, ok := pl.(*ikev2.EncryptedPayloadNonce); ok {
				ni = nonce.NonceData
			}
		}

		nr := bytes.Repeat([]byte{0x66}, 32)
		initResp := ikev2.NewIKEPacket()
		initResp.Header = &ikev2.IKEHeader{SPIi: req2.Header.SPIi, SPIr: 0x123456789abcdef0, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
		initResp.Payloads = []ikev2.Payload{
			&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sa2.Proposals[0]}},
			&ikev2.EncryptedPayloadKE{DHGroup: ikev2.MODP_1024_bit, KEData: peerPub},
			&ikev2.EncryptedPayloadNonce{NonceData: nr},
		}
		initRespWire, err := initResp.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(initRespWire, addr); err != nil {
			t.Fatal(err)
		}

		// 3rd packet: protected IKE_AUTH using SHA1 + AES-CBC-128 derived from DH2 shared secret.
		n3, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		authWire := bytes.Clone(buf[:n3])
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect stop after IKE_AUTH: %v", err)
		}

		indepSecret := new(big.Int).Exp(new(big.Int).SetBytes(ke2.KEData), peerPriv, p1024).FillBytes(make([]byte, 128))
		keys := independentIKEKeys(sha1.New, 20, indepSecret, ni, nr, initResp.Header.SPIi, initResp.Header.SPIr, 132)
		skAi := keys[20:40]
		skEi := keys[60:76]

		mac := hmac.New(sha1.New, skAi)
		mac.Write(authWire[:len(authWire)-12])
		if !hmac.Equal(mac.Sum(nil)[:12], authWire[len(authWire)-12:]) {
			t.Fatal("independent peer rejected HMAC-SHA1-96 ICV on DH2 IKE_AUTH")
		}
		block, err := aes.NewCipher(skEi)
		if err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, len(authWire)-60)
		cipher.NewCBCDecrypter(block, authWire[32:48]).CryptBlocks(plain, authWire[48:len(authWire)-12])
		if !bytes.Contains(plain, []byte("synthetic@invalid")) {
			t.Fatal("independent peer could not decrypt identity in DH2 IKE_AUTH")
		}
	})
}
