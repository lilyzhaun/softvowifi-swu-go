package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
)

func Test_AKAStructure_whenEncodedResponseChanges(t *testing.T) {
	for _, scenario := range []struct {
		name                     string
		resOctets                int
		mutate                   func([]byte)
		resign                   bool
		bits                     int
		padding, identifier, mac bool
	}{
		{"RES4", 4, nil, false, 32, true, true, true},
		{"RES16", 16, nil, false, 128, true, true, true},
		{"RES5 padded", 5, nil, false, 40, true, true, true},
		{"nonzero padding", 5, func(raw []byte) { raw[17] = 1 }, true, 40, false, true, true},
		{"declared bits differ", 4, func(raw []byte) { raw[11] = 24 }, true, 24, true, true, true},
		{"identifier differs", 4, func(raw []byte) { raw[1] ^= 1 }, true, 32, true, false, true},
		{"local MAC invalid", 4, func(raw []byte) { raw[len(raw)-1] ^= 1 }, false, 32, true, true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, scenario.resOctets), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
			keys := referenceAKAKeys(provider, false)
			raw := referenceResponse(provider.res, keys[16:32], false)
			if scenario.mutate != nil {
				scenario.mutate(raw)
			}
			if scenario.resign {
				clear(raw[len(raw)-16:])
				mac := hmac.New(sha1.New, keys[16:32])
				mac.Write(raw)
				copy(raw[len(raw)-16:], mac.Sum(nil)[:16])
			}
			original := bytes.Clone(raw)
			log, output := diagnosticLogger()
			sess := NewSession(&Config{}, log)

			sess.logAKAResponseStructure(raw, keys[16:32], akaResponseExpectation{identifier: 0xa7, resOctets: scenario.resOctets})

			events := structureEvents(t, output)
			if len(events) != 1 {
				t.Fatal("missing local response check")
			}
			event := events[0]
			if event.Phase != "response" || event.ParseError != "" || event.RESOctets == nil || *event.RESOctets != scenario.resOctets || event.RESBits == nil || *event.RESBits != scenario.bits || event.PaddingZero == nil || *event.PaddingZero != scenario.padding || event.IdentifierMatches == nil || *event.IdentifierMatches != scenario.identifier || event.LocalMACValid == nil || *event.LocalMACValid != scenario.mac {
				t.Fatal("encoded metadata not independently checked")
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("local check mutated encoded response")
			}
			assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik, keys[16:32])
		})
	}
}

func Test_AKAStructure_whenEncodedResponseMalformed(t *testing.T) {
	key := bytes.Repeat([]byte{0x4b}, 16)
	valid := referenceResponse(bytes.Repeat([]byte{0x52}, 4), key, false)
	for _, scenario := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"short", []byte{2, 1, 0, 3}},
		{"short method", []byte{2, 1, 0, 6, 23, 1}},
		{"wrong method", (&eap.EAPPacket{Code: 2, Type: 50, Subtype: 1}).Encode()},
		{"wrong code", (&eap.EAPPacket{Code: 1, Type: 23, Subtype: 1}).Encode()},
		{"missing attributes", (&eap.EAPPacket{Code: 2, Type: 23, Subtype: 1}).Encode()},
		{"zero length attribute", (&eap.EAPPacket{Code: 2, Type: 23, Subtype: 1, Data: []byte{3, 0, 0, 0}}).Encode()},
		{"truncated frame", valid[:len(valid)-1]},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			log, output := diagnosticLogger()
			sess := NewSession(&Config{}, log)
			sess.logAKAResponseStructure(scenario.raw, key, akaResponseExpectation{identifier: 0xa7, resOctets: 4})
			events := structureEvents(t, output)
			if len(events) != 1 || events[0].ParseError != "invalid_response" || events[0].RESOctets != nil || events[0].LocalMACValid != nil || events[0].IdentifierMatches != nil {
				t.Fatal("malformed response emitted unvalidated facts")
			}
			assertDiagnosticPrivacy(t, output, key)
		})
	}
}

func Test_AKAStructure_whenOtherMethodOrSubtype(t *testing.T) {
	for _, raw := range [][]byte{
		diagnosticChallenge(50),
		(&eap.EAPPacket{Code: 1, Type: 23, Subtype: 5}).Encode(),
		(&eap.EAPPacket{Code: 1, Type: 1}).Encode(),
	} {
		log, output := diagnosticLogger()
		sess := NewSession(&Config{SIM: &diagnosticSIM{}}, log)
		_, _ = sess.handleEAP(raw)
		if len(structureEvents(t, output)) != 0 {
			t.Fatal("AKA-only structural claim emitted for another path")
		}
	}
}
