package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

const identityNAI = "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"

func identityRequest(id byte, attrs ...byte) []byte {
	raw := append([]byte{1, id, 0, 0, 23, 5, 0, 0}, attrs...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	return raw
}

func identityResponse(id byte, identity string) []byte {
	words := (4 + len(identity) + 3) / 4
	raw := make([]byte, 8+words*4)
	copy(raw, []byte{2, id, 0, byte(len(raw)), 23, 5, 0, 0, 14, byte(words)})
	binary.BigEndian.PutUint16(raw[10:12], uint16(len(identity)))
	copy(raw[12:], identity)
	return raw
}

func identityEAP(t *testing.T, sess *Session, request []byte) []byte {
	t.Helper()
	payloads, err := sess.handleEAP(request)
	if err != nil || len(payloads) != 1 {
		t.Fatalf("handleEAP: %v, payloads=%d", err, len(payloads))
	}
	response, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
	if !ok {
		t.Fatal("missing wire EAP")
	}
	return response.EAPMessage
}

func identitySession(t *testing.T) (*Session, *vectorSIM) {
	t.Helper()
	provider := &vectorSIM{
		res: referenceHex(t, "2b1c2593f5af288a3766cada9ce23fb9"),
		ck:  referenceHex(t, "070ac6e26957e00c83a4b577210a8aec"),
		ik:  referenceHex(t, "0b48923d40b48c476b0ee8a43f780356"),
	}
	log, _ := diagnosticLogger()
	return NewSession(&Config{SIM: provider}, log), provider
}

func Test_AKAIdentity_permanentNAI_whenValidRequest(t *testing.T) {
	for _, requestType := range []byte{10, 13, 17} {
		t.Run(fmt.Sprint(requestType), func(t *testing.T) {
			sess, provider := identitySession(t)
			got := identityEAP(t, sess, identityRequest(0xcd, requestType, 1, 0, 0))
			if !bytes.Equal(got, identityResponse(0xcd, identityNAI)) || provider.calls != 0 {
				t.Fatal("identity wire or SIM authentication count differs")
			}
		})
	}
}

func Test_AKAIdentity_clientError_whenMalformedRequest(t *testing.T) {
	for _, attrs := range [][]byte{
		nil, {13, 0, 0, 0}, {13, 2, 0, 0}, {13, 2, 0, 0, 0, 0, 0, 0},
		{13, 1, 0, 0, 13, 1, 0, 0}, {13, 1, 0, 0, 10, 1, 0, 0},
		{13, 1, 0, 0, 11, 1, 0, 0}, {13, 1, 0, 0, 129, 1, 0, 0},
		{13, 1, 0, 0, 130, 1, 0, 0}, {13, 1, 0, 0, 99, 1, 0, 0}, {13, 1, 0, 0, 7},
	} {
		t.Run(fmt.Sprintf("%x", attrs), func(t *testing.T) {
			sess, provider := identitySession(t)
			got := identityEAP(t, sess, identityRequest(0xcd, attrs...))
			if !bytes.Equal(got, []byte{2, 0xcd, 0, 12, 23, 14, 0, 0, 22, 1, 0, 0}) || provider.calls != 0 {
				t.Fatal("malformed identity did not produce unable-to-process")
			}
			if _, err := sess.handleEAP(identityRequest(0xce, 13, 1, 0, 0)); err == nil {
				t.Fatal("client error did not terminate authentication")
			}
		})
	}
}

func identityChallenge(t *testing.T, key, checkcode []byte) []byte {
	t.Helper()
	raw := referenceHex(t, "01ce00441701000001050000a789798e3e75560ea3ea5e41a043753a02050000236c38dd8772000165a96f168f5c14e20b0500008e733917f65c54ee820195efb94246dc")
	raw = append(raw[:48], append(bytes.Clone(checkcode), raw[48:]...)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	clear(raw[len(raw)-16:])
	mac := hmac.New(sha1.New, key)
	mac.Write(raw)
	copy(raw[len(raw)-16:], mac.Sum(nil)[:16])
	return raw
}

func Test_AKAIdentity_challengeUsesLastWireIdentity_whenOuterDiffers(t *testing.T) {
	sess, provider := identitySession(t)
	sess.fastReauthCtx.SaveReauthData("outer-test@android.net", make([]byte, 20), make([]byte, 16), make([]byte, 16))
	outer := identityEAP(t, sess, []byte{1, 1, 0, 5, 1})
	if string(outer[5:]) == identityNAI {
		t.Fatal("fixture must have distinct outer and inner identity")
	}
	request := identityRequest(0xcd, 13, 1, 0, 0)
	response := identityEAP(t, sess, request)
	if !bytes.Equal(response, identityResponse(0xcd, identityNAI)) {
		t.Fatal("permanent-only identity policy changed")
	}
	keys := referenceAKAKeys(provider, false)
	got := identityEAP(t, sess, identityChallenge(t, keys[16:32], nil))
	want := referenceHex(t, "02ce003017010000030500802b1c2593f5af288a3766cada9ce23fb90b050000e5a74ae0840c1e75e0c471d5a915ab7f")
	clear(want[len(want)-16:])
	mac := hmac.New(sha1.New, keys[16:32])
	mac.Write(want)
	copy(want[len(want)-16:], mac.Sum(nil)[:16])
	if !bytes.Equal(got, want) || !bytes.Equal(sess.MSK, keys[32:96]) {
		t.Fatal("AOSP challenge rebound to production NAI differs from independent reference")
	}
}

func Test_AKAIdentity_checkcode_whenIdentityExchanged(t *testing.T) {
	for _, scenario := range []string{"valid", "invalid", "empty", "short", "duplicate", "extension-missing", "extension-valid"} {
		t.Run(scenario, func(t *testing.T) {
			sess, provider := identitySession(t)
			request := identityRequest(0xcd, 13, 1, 0x12, 0x34)
			if scenario == "extension-missing" || scenario == "extension-valid" {
				request = identityRequest(0xcd, 13, 1, 0, 0, 250, 1, 0x56, 0x78)
			}
			response := identityEAP(t, sess, request)
			digest := sha1.Sum(append(bytes.Clone(request), response...))
			checkcode := append([]byte{134, 6, 0x9a, 0xbc}, digest[:]...)
			switch scenario {
			case "invalid":
				checkcode[4] ^= 1
			case "empty":
				checkcode = []byte{134, 1, 0, 0}
			case "short":
				checkcode = []byte{134, 2, 0, 0, 1, 2, 3, 4}
			case "duplicate":
				checkcode = append(checkcode, checkcode...)
			case "extension-missing":
				checkcode = nil
			}
			keys := referenceAKAKeys(provider, false)
			payloads, err := sess.handleEAP(identityChallenge(t, keys[16:32], checkcode))
			valid := scenario == "valid" || scenario == "extension-valid"
			if valid {
				if err != nil || len(payloads) != 1 || len(sess.MSK) != 64 {
					t.Fatalf("valid checkcode rejected: %v", err)
				}
			} else if len(sess.MSK) != 0 || (err == nil && len(payloads) == 0) {
				t.Fatal("invalid checkcode accepted or missing failure response")
			} else if err == nil {
				packet, parseErr := eap.Parse(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage)
				if parseErr != nil || packet.Subtype != 14 {
					t.Fatal("expected client error for checkcode")
				}
			}
		})
	}
}
