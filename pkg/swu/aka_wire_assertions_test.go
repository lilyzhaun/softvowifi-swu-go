package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

type akaWirePayload struct {
	kind byte
	body []byte
}

func parseAKAWirePayloads(t *testing.T, first byte, plain []byte) []akaWirePayload {
	t.Helper()
	var payloads []akaWirePayload
	for kind := first; kind != 0; {
		if len(plain) < 4 {
			t.Fatal("truncated inner generic header")
		}
		size := int(binary.BigEndian.Uint16(plain[2:4]))
		if size < 4 || size > len(plain) || plain[1] != 0 {
			t.Fatal("invalid inner payload extent or flags")
		}
		payloads = append(payloads, akaWirePayload{kind: kind, body: bytes.Clone(plain[4:size])})
		kind = plain[0]
		plain = plain[size:]
	}
	if len(plain) != 0 {
		t.Fatal("unparsed bytes after final inner payload")
	}
	return payloads
}

func assertAKAWireInitial(t *testing.T, payloads []akaWirePayload) {
	t.Helper()
	wantTypes := []byte{35, 36, 47, 33, 44, 45, 41, 41}
	if len(payloads) != len(wantTypes) {
		t.Fatal("unexpected AUTH1 payload count")
	}
	for index, kind := range wantTypes {
		if payloads[index].kind != kind {
			t.Fatalf("AUTH1 payload %d has unexpected type", index)
		}
	}
	identity := []byte("0" + "00101" + "0000000001" + "@nai.epc.mnc001.mcc001.3gppnetwork.org")
	if !bytes.Equal(payloads[0].body, append([]byte{3, 0, 0, 0}, identity...)) {
		t.Fatal("AUTH1 IDi differs from synthetic permanent NAI")
	}
	if !bytes.Equal(payloads[1].body, []byte{2, 0, 0, 0, 'i', 'm', 's'}) {
		t.Fatal("AUTH1 IDr/APN is not ims")
	}
	cp := []byte{1, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 20, 0, 0, 0, 8, 0, 0, 0, 10, 0, 0, 0, 21, 0, 0, 0x40, 6, 0, 0}
	if len(payloads[2].body) >= 20 {
		gotLen := int(binary.BigEndian.Uint16(payloads[2].body[18:20]))
		if gotLen != 0 {
			t.Fatalf("AUTH1 CFG_REQUEST INTERNAL_IP6_ADDRESS value length must be 0, got %d", gotLen)
		}
	}
	if !bytes.Equal(payloads[2].body, cp) {
		t.Fatal("AUTH1 CFG_REQUEST dual-stack attributes differ")
	}
	// RFC 5998 section 3: zero Protocol ID/SPI size, type 16417, no additional data.
	if !bytes.Equal(payloads[6].body, []byte{0, 0, 0x40, 0x21}) {
		t.Fatalf("AUTH1 EAP_ONLY must be 00 00 40 21, got %x", payloads[6].body)
	}
	if !bytes.Equal(payloads[7].body, []byte{0, 0, 0x40, 0}) {
		t.Fatal("AUTH1 INITIAL_CONTACT changed")
	}
}

func verifyAKAWireMAC(raw, kAut []byte) error {
	if len(raw) < 8 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
		return errors.New("invalid EAP extent")
	}
	unsigned := bytes.Clone(raw)
	macStart := -1
	for offset := 8; offset < len(raw); {
		if len(raw)-offset < 4 {
			return errors.New("truncated AKA attribute")
		}
		size := int(raw[offset+1]) * 4
		if size < 4 || size > len(raw)-offset {
			return errors.New("invalid AKA attribute extent")
		}
		if raw[offset] == 11 {
			if macStart >= 0 || size != 20 || raw[offset+2] != 0 || raw[offset+3] != 0 {
				return errors.New("invalid or repeated AT_MAC")
			}
			macStart = offset + 4
			clear(unsigned[macStart : macStart+16])
		}
		offset += size
	}
	if macStart < 0 {
		return errors.New("missing AT_MAC")
	}
	mac := hmac.New(sha1.New, kAut)
	mac.Write(unsigned)
	if !hmac.Equal(mac.Sum(nil)[:16], raw[macStart:macStart+16]) {
		return errors.New("independent EAP MAC mismatch")
	}
	return nil
}

func Test_AKAWireMACRejectsChanges_whenAttributeIsNotLast(t *testing.T) {
	key := bytes.Repeat([]byte{0x4b}, 16)
	valid := referenceResponse([]byte{0x60, 0x61, 0x62, 0x63, 0x64}, key, false)
	macStart := len(valid) - 16
	clear(valid[macStart:])
	valid = append(valid, 134, 1, 0, 0)
	binary.BigEndian.PutUint16(valid[2:4], uint16(len(valid)))
	mac := hmac.New(sha1.New, key)
	mac.Write(valid)
	copy(valid[macStart:macStart+16], mac.Sum(nil)[:16])
	for _, scenario := range []struct {
		name   string
		offset int
	}{
		{"intact", -1},
		{"identifier", 1},
		{"RES", 12},
		{"RES padding", 17},
		{"MAC", macStart},
		{"attribute after MAC", len(valid) - 1},
		{"EAP length", 3},
		{"attribute length", 9},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			raw := bytes.Clone(valid)
			if scenario.offset >= 0 {
				raw[scenario.offset] ^= 1
			}

			err := verifyAKAWireMAC(raw, key)

			if (err != nil) != (scenario.offset >= 0) {
				t.Fatal("independent MAC oracle accepted tampering or rejected intact packet")
			}
		})
	}
}

func Test_AUTH1CP_requestsEmptyIPv6_whenFreshConfig(t *testing.T) {
	// Given: AOSP fresh CFG_REQUEST encodes INTERNAL_IP6_ADDRESS with value length 0.
	log, _ := diagnosticLogger()
	session := NewSession(&Config{SIM: &vectorSIM{}, APN: "ims"}, log)
	session.childSPI = 0x12345678

	// When
	payloads, err := session.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}

	// Then
	cp, ok := payloads[2].(*ikev2.EncryptedPayloadCP)
	if !ok || cp.CFGType != ikev2.CFG_REQUEST || len(cp.Attributes) != 7 {
		t.Fatal("AUTH1 CP is not a 7-attribute CFG_REQUEST")
	}
	if cp.Attributes[3].Type != ikev2.INTERNAL_IP6_ADDRESS || len(cp.Attributes[3].Value) != 0 {
		t.Fatalf("AUTH1 CFG_REQUEST INTERNAL_IP6_ADDRESS value length must be 0, got %d", len(cp.Attributes[3].Value))
	}
	if cp.Attributes[6].Type != ikev2.ASSIGNED_PCSCF_IP6_ADDRESS || len(cp.Attributes[6].Value) != 0 {
		t.Fatal("AUTH1 CFG_REQUEST must keep empty ASSIGNED_PCSCF_IP6_ADDRESS")
	}
	packet := &ikev2.IKEPacket{Header: &ikev2.IKEHeader{}, Payloads: payloads}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	assertAKAWireInitial(t, parseAKAWirePayloads(t, 35, raw[28:]))
}
