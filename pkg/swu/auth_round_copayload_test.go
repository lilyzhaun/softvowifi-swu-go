package swu

import (
	"bytes"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func copayloadSession(t *testing.T) (*Session, *vectorSIM, []byte) {
	t.Helper()
	p := &vectorSIM{res: bytes.Repeat([]byte{0x52}, 8), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
	s := NewSession(&Config{SIM: p, IMEI: "123456789012345"}, nil)
	return s, p, referenceAKAKeys(p, false)[16:32]
}

func copayloadRequest(code uint16) *ikev2.EncryptedPayloadNotify {
	return &ikev2.EncryptedPayloadNotify{NotifyType: code, NotifyData: []byte{0, 1, 1}}
}

func TestAUTHRoundCombinesVerifiedChallengeAndDeviceIdentity(t *testing.T) {
	for _, code := range []uint16{16432, 41101} {
		for _, reverse := range []bool{false, true} {
			s, p, key := copayloadSession(t)
			challenge := &ikev2.EncryptedPayloadEAP{EAPMessage: referenceChallenge(key, false)}
			input := []ikev2.Payload{challenge, copayloadRequest(code)}
			if reverse {
				input[0], input[1] = input[1], input[0]
			}
			response, done, err := s.processIKEAuthEAPRound(input)
			if err != nil || done || len(response) != 2 {
				t.Fatalf("authenticated round lost a requested payload: %v", err)
			}
			if p.calls != 1 || !bytes.Equal(response[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, referenceResponse(p.res, key, false)) {
				t.Fatal("combined reply changed independent AKA wire/MAC")
			}
			n := response[1].(*ikev2.EncryptedPayloadNotify)
			if n.NotifyType != code || !bytes.Equal(n.NotifyData, referenceHex(t, "00090121436587092143f5")) {
				t.Fatal("combined identity reply changed type/code/TBCD")
			}
		}
	}
}

func TestAUTHRoundStandaloneDeviceRequestRemainsSupported(t *testing.T) {
	for _, code := range []uint16{16432, 41101} {
		s, _, key := copayloadSession(t)
		if _, err := s.handleEAP(referenceChallenge(key, false)); err != nil {
			t.Fatal(err)
		}
		response, done, err := s.processIKEAuthEAPRound([]ikev2.Payload{copayloadRequest(code)})
		if err != nil || done || len(response) != 1 {
			t.Fatalf("standalone authenticated request omitted: %v", err)
		}
		if response[0].(*ikev2.EncryptedPayloadNotify).NotifyType != code {
			t.Fatal("standalone reply did not preserve request code")
		}
	}
}

func TestAUTHRoundNeverDisclosesDeviceBeforeAuthenticationOrOnFailure(t *testing.T) {
	for _, kind := range []string{"early", "identity request", "bad MAC", "diagnostic bypass", "EAP failure", "IKE error", "duplicate EAP", "duplicate device", "empty request", "bad length", "reserved type", "identity value present", "SPI present", "missing equipment"} {
		t.Run(kind, func(t *testing.T) {
			s, p, key := copayloadSession(t)
			n := copayloadRequest(41101)
			challenge := &ikev2.EncryptedPayloadEAP{EAPMessage: referenceChallenge(key, false)}
			input := []ikev2.Payload{challenge, n}
			switch kind {
			case "early":
				input = []ikev2.Payload{n}
			case "identity request":
				challenge.EAPMessage = []byte{1, 1, 0, 12, 23, 5, 0, 0, 13, 1, 0, 0}
			case "bad MAC":
				challenge.EAPMessage[len(challenge.EAPMessage)-1] ^= 1
			case "diagnostic bypass":
				s.cfg.DisableEAPMACValidation = true
			case "EAP failure":
				challenge.EAPMessage = []byte{4, 1, 0, 4}
			case "IKE error":
				input = append(input, &ikev2.EncryptedPayloadNotify{NotifyType: 24})
			case "duplicate EAP":
				input = append(input, challenge)
			case "duplicate device":
				input = append(input, copayloadRequest(16432))
			case "empty request":
				n.NotifyData = nil
			case "bad length":
				n.NotifyData = []byte{0, 2, 1}
			case "reserved type":
				n.NotifyData = []byte{0, 1, 3}
			case "identity value present":
				n.NotifyData = []byte{0, 2, 1, 0}
			case "SPI present":
				n.SPI = []byte{1}
			case "missing equipment":
				s.cfg.IMEI = ""
			}
			response, _, err := s.processIKEAuthEAPRound(input)
			if err == nil || response != nil {
				t.Fatal("unverified or malformed round returned an equipment identity")
			}
			if kind == "duplicate EAP" || kind == "duplicate device" || kind == "empty request" || kind == "bad length" || kind == "reserved type" || kind == "identity value present" || kind == "SPI present" || kind == "IKE error" {
				if p.calls != 0 {
					t.Fatal("invalid round consumed SIM before full payload validation")
				}
			}
		})
	}
}

func TestAUTHRoundNotificationFailureACKExcludesEquipment(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		s, _, key := copayloadSession(t)
		code := uint16(0)
		if authenticated {
			if _, err := s.handleEAP(referenceChallenge(key, false)); err != nil {
				t.Fatal(err)
			}
		} else {
			code = 0x4000
			key = nil
		}
		response, _, err := s.processIKEAuthEAPRound([]ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: notificationWire(code, key)}, copayloadRequest(41101)})
		if err != nil {
			t.Fatal(err)
		}
		notificationACK(t, response, key)
	}
}

func TestRequestedDeviceIdentityUsesOnlyAvailableDigits(t *testing.T) {
	for _, identity := range []string{"", "1", "12345678901234X", "000000000000000"} {
		s := NewSession(&Config{IMEI: identity}, nil)
		if _, err := s.buildDeviceIdentityResponse(1); err == nil {
			t.Fatal("missing/invalid equipment identity synthesized or accepted")
		}
	}
	s := NewSession(&Config{IMEI: "123456789012345"}, nil)
	pls, err := s.buildDeviceIdentityResponse(2)
	if err != nil || !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadNotify).NotifyData, referenceHex(t, "00090121436587092143f5")) {
		t.Fatal("unavailable IMEISV was fabricated rather than replying available IMEI")
	}
	s.cfg.IMEI = "1234567890123456"
	pls, err = s.buildDeviceIdentityResponse(1)
	if err != nil || !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadNotify).NotifyData, referenceHex(t, "0009022143658709214365")) {
		t.Fatal("available IMEISV changed or was truncated")
	}
}

type copayloadEquipmentSIM struct {
	vectorSIM
	equipmentCalls int
}

func (p *copayloadEquipmentSIM) GetIMEI() (string, error) {
	p.equipmentCalls++
	return "123456789012345", nil
}

func TestAUTHRoundReadsSIMEquipmentOnlyAfterNetworkMAC(t *testing.T) {
	for _, valid := range []bool{false, true} {
		s, base, key := copayloadSession(t)
		p := &copayloadEquipmentSIM{vectorSIM: *base}
		s.cfg.SIM = p
		s.cfg.IMEI = ""
		raw := referenceChallenge(key, false)
		if !valid {
			raw[len(raw)-1] ^= 1
		}
		response, _, err := s.processIKEAuthEAPRound([]ikev2.Payload{copayloadRequest(41101), &ikev2.EncryptedPayloadEAP{EAPMessage: raw}})
		if valid {
			if err != nil || len(response) != 2 || p.equipmentCalls != 1 {
				t.Fatal("available provider equipment was not used after MAC")
			}
		} else if err == nil || p.equipmentCalls != 0 {
			t.Fatal("invalid network challenge accessed equipment provider")
		}
	}
}
