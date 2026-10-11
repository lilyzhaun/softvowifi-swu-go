package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/sim"
)

type diagnosticSIM struct {
	imsiCalls  int
	akaCalls   int
	failure    error
	rand, autn []byte
}

func (provider *diagnosticSIM) GetIMSI() (string, error) {
	provider.imsiCalls++
	return "001010000000001", nil
}

func (provider *diagnosticSIM) CalculateAKA(rand, autn []byte) ([]byte, []byte, []byte, []byte, error) {
	provider.akaCalls++
	provider.rand, provider.autn = bytes.Clone(rand), bytes.Clone(autn)
	return []byte("PRIVATE-RES"), []byte("PRIVATE-CK-12345"), []byte("PRIVATE-IK-12345"), []byte("PRIVATE-AUTS01"), provider.failure
}

func (provider *diagnosticSIM) Close() error { return nil }

func diagnosticChallenge(method uint8) []byte {
	var attrs []byte
	for _, attr := range []*eap.Attribute{
		{Type: eap.AT_MAC, Value: append([]byte{0, 0}, []byte("PRIVATE-MAC-1234")...)},
		{Type: eap.AT_AUTN, Value: append([]byte{0, 0}, []byte("PRIVATE-AUTN-123")...)},
		{Type: eap.AT_RAND, Value: append([]byte{0, 0}, []byte("PRIVATE-RAND-123")...)},
		{Type: eap.AT_ENCR_DATA, Value: []byte("PRIVATE-CIPHERTEXT")},
		{Type: 250, Value: []byte("PRIVATE-UNKNOWN-ATTRIBUTE")},
	} {
		attrs = append(attrs, attr.Encode()...)
	}
	return (&eap.EAPPacket{Code: 1, Identifier: 7, Type: method, Subtype: 1, Data: attrs}).Encode()
}

func diagnosticPrimeChallenge() []byte {
	raw := diagnosticChallenge(50)
	for offset := 8; offset < len(raw); offset += int(raw[offset+1]) * 4 {
		if raw[offset] == eap.AT_AUTN {
			raw[offset+10] |= 0x80
		}
	}
	raw = append(raw, 23, 2, 0, 4, 'W', 'L', 'A', 'N', 24, 1, 0, 1)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	return raw
}

func Test_EAPDiagnostics_whenSIMAKACompletes(t *testing.T) {
	for _, method := range []uint8{23, 50} {
		for _, scenario := range []struct {
			name    string
			failure error
		}{
			{"success", nil},
			{"sync_failure", fmt.Errorf("PRIVATE-ERROR: %w", sim.ErrSyncFailure)},
			{"failure", errors.New("PRIVATE-ERROR")},
		} {
			t.Run(fmt.Sprintf("%d/%s", method, scenario.name), func(t *testing.T) {
				log, output := diagnosticLogger()
				provider := &diagnosticSIM{failure: scenario.failure}
				sess := NewSession(&Config{SIM: provider}, log)
				raw := diagnosticChallenge(method)
				wantAutn := []byte("PRIVATE-AUTN-123")
				if method == 50 {
					raw = diagnosticPrimeChallenge()
					wantAutn[6] |= 0x80
					sess.akaIdentity.outer = []byte("public-diagnostic-prime")
				}
				payloads, err := sess.handleEAP(raw)
				if provider.akaCalls != 1 || !bytes.Equal(provider.rand, []byte("PRIVATE-RAND-123")) || !bytes.Equal(provider.autn, wantAutn) {
					t.Fatal("SIM invocation changed")
				}
				switch scenario.name {
				case "sync_failure":
					if err != nil || len(payloads) != 1 {
						t.Fatal("sync response changed")
					}
					packet, parseErr := eap.Parse(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage)
					if parseErr != nil || packet.Subtype != eap.SubtypeSyncFailure || packet.Type != method {
						t.Fatal("missing AUTS response")
					}
				case "failure", "success":
					if err == nil {
						t.Fatal("SIM failure or invalid MAC no longer rejected")
					}
				}
				events := diagnosticEvents(t, output)
				if len(events) != 3 {
					t.Fatalf("diagnostic count = %d, want received/invoke/result", len(events))
				}
				wantTypes := []int{1, 2, 11, 130, 250}
				if method == 50 {
					wantTypes = []int{1, 2, 11, 23, 24, 130, 250}
				}
				if !reflect.DeepEqual(events[0].AttrTypes, wantTypes) || events[0].Type != int(method) {
					t.Fatal("attribute metadata incorrect")
				}
				if events[1].Message != "SIM AKA" || events[1].Phase != "invoke" || !events[1].Invoked || events[1].Result != "" {
					t.Fatal("missing SIM entry")
				}
				if events[2].Phase != "result" || !events[2].Invoked || events[2].Result != scenario.name {
					t.Fatal("incorrect SIM result enum")
				}
				assertDiagnosticPrivacy(t, output, []byte("PRIVATE-"), []byte("001010000000001"))
			})
		}
	}
}

func Test_EAPDiagnostics_whenValidPrimeChallengeDoesNotCacheAsAKA(t *testing.T) {
	log, output := diagnosticLogger()
	provider := &diagnosticSIM{}
	callbackCalls := 0
	pseudonym := "PRIVATE-PRIME-PSEUDONYM"
	cfg := &Config{SIM: provider, OnFastReauthUpdate: func(identity string, mk, kAut, kEncr []byte) {
		callbackCalls++
		if identity != pseudonym || len(mk) != 32 || len(kAut) != 32 || kEncr != nil {
			t.Error("prime callback values changed")
		}
	}}
	sess := NewSession(cfg, log)
	identity := []byte("public-diagnostic-prime")
	sess.akaIdentity.outer = bytes.Clone(identity)
	packet, err := eap.Parse(diagnosticPrimeChallenge())
	if err != nil {
		t.Fatal(err)
	}
	value := binary.BigEndian.AppendUint16(nil, uint16(len(pseudonym)))
	packet.Data = append(packet.Data, (&eap.Attribute{Type: eap.AT_NEXT_REAUTH_ID, Value: append(value, pseudonym...)}).Encode()...)
	raw := packet.Encode()
	clear(raw[12:28])
	autn := []byte("PRIVATE-AUTN-123")
	autn[6] |= 0x80
	_, keyMaterial := primeIndependentMaterial([]byte("PRIVATE-CK-12345"), []byte("PRIVATE-IK-12345"), autn, identity, "WLAN")
	mac := hmac.New(sha256.New, keyMaterial[16:48])
	mac.Write(raw)
	copy(raw[12:28], mac.Sum(nil)[:16])
	response, err := sess.handleEAP(raw)
	if err != nil || len(response) != 1 {
		t.Fatal("valid prime challenge failed")
	}
	if callbackCalls != 0 || provider.akaCalls != 1 || provider.imsiCalls != 0 || sess.fastReauthCtx.ReauthID != "" || !bytes.Equal(sess.MSK, keyMaterial[80:144]) {
		t.Fatal("Prime falsely cached Type23 fast data or lost standard MSK/actual identity")
	}
	assertDiagnosticPrivacy(t, output, []byte("PRIVATE-"), []byte("001010000000001"))
}

func Test_EAPDiagnostics_whenValidChallengeUpdatesPseudonym(t *testing.T) {
	log, output := diagnosticLogger()
	provider := &diagnosticSIM{}
	callbackCalls := 0
	pseudonym := "PRIVATE-NEXT-PSEUDONYM"
	cfg := &Config{SIM: provider, OnFastReauthUpdate: func(identity string, mk, kAut, kEncr []byte) {
		callbackCalls++
		if identity != pseudonym || len(mk) != 20 || len(kAut) != 16 || len(kEncr) != 16 {
			t.Error("callback values changed")
		}
	}}
	sess := NewSession(cfg, log)
	packet, err := eap.Parse(diagnosticChallenge(23))
	if err != nil {
		t.Fatal(err)
	}
	value := binary.BigEndian.AppendUint16(nil, uint16(len(pseudonym)))
	packet.Data = append(packet.Data, (&eap.Attribute{Type: eap.AT_NEXT_REAUTH_ID, Value: append(value, pseudonym...)}).Encode()...)
	raw := packet.Encode()
	clear(raw[12:28])
	master := sha1.New()
	master.Write([]byte(buildNAI("001010000000001", cfg)))
	master.Write([]byte("PRIVATE-IK-12345"))
	master.Write([]byte("PRIVATE-CK-12345"))
	keyMaterial := crypto.NewFIPS1862PRFSHA1(master.Sum(nil)).Bytes(nil, 48)
	mac := hmac.New(sha1.New, keyMaterial[16:32])
	mac.Write(raw)
	copy(raw[12:28], mac.Sum(nil)[:16])
	response, err := sess.handleEAP(raw)
	if err != nil || len(response) != 1 {
		t.Fatal("valid challenge failed")
	}
	if callbackCalls != 1 || provider.akaCalls != 1 || provider.imsiCalls != 2 || sess.fastReauthCtx.ReauthID != pseudonym {
		t.Fatal("callback/SIM behavior changed")
	}
	assertDiagnosticPrivacy(t, output, []byte("PRIVATE-"), []byte("001010000000001"))
}
