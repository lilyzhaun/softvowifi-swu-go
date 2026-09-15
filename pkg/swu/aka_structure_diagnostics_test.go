package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

type akaStructureEvent struct {
	Level             string  `json:"level"`
	Time              float64 `json:"ts"`
	Message           string  `json:"msg"`
	Phase             string  `json:"phase"`
	CheckcodeStatus   string  `json:"checkcode_status"`
	CheckcodeOctets   *int    `json:"checkcode_octets"`
	CheckcodeEmpty    *bool   `json:"checkcode_empty"`
	BiddingStatus     string  `json:"bidding_status"`
	BiddingD          *bool   `json:"bidding_d"`
	MACStatus         string  `json:"mac_status"`
	Verified          bool    `json:"verified"`
	DerivationOrder   string  `json:"derivation_order"`
	RESOctets         *int    `json:"res_len_octets"`
	RESBits           *int    `json:"declared_res_bits"`
	PaddingZero       *bool   `json:"padding_zero"`
	IdentifierMatches *bool   `json:"eap_identifier_matches"`
	LocalMACValid     *bool   `json:"local_mac_valid"`
	ParseError        string  `json:"parse_error"`
}

func structureEvents(t *testing.T, output *bytes.Buffer) []akaStructureEvent {
	t.Helper()
	var events []akaStructureEvent
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			return events
		} else if err != nil {
			t.Fatal("invalid serialized log")
		}
		var envelope struct {
			Message string `json:"msg"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal("invalid log envelope")
		}
		if envelope.Message != "AKA structure" {
			continue
		}
		var event akaStructureEvent
		strict := json.NewDecoder(bytes.NewReader(raw))
		strict.DisallowUnknownFields()
		if err := strict.Decode(&event); err != nil {
			t.Fatal("structure log violates scalar field whitelist")
		}
		if event.Level != "info" {
			t.Fatal("structure event unavailable at production Info")
		}
		events = append(events, event)
	}
}

func Test_AKAStructure_whenChallengeUsesActualBranch(t *testing.T) {
	for _, scenario := range []struct {
		name                                         string
		resOctets                                    int
		reverse, skipped, tampered                   bool
		checkcode, bidding                           []byte
		checkStatus, biddingStatus, macStatus, order string
	}{
		{"empty D0", 4, false, false, false, []byte{0x43, 0x4b}, []byte{0x43, 0x4b}, "valid", "valid", "verified", "ik_ck"},
		{"empty D1 reverse", 16, true, false, false, []byte{0x43, 0x4b}, []byte{0xc3, 0x4b}, "valid", "valid", "verified", "ck_ik"},
		{"bypass not verified", 4, true, true, true, []byte{0, 0}, []byte{0x80, 0}, "valid", "valid", "skipped", ""},
		{"invalid MAC", 16, false, false, true, []byte{0, 0}, []byte{0, 0}, "valid", "valid", "invalid", ""},
		{"malformed bidding attribute", 4, false, false, false, []byte{0, 0}, bytes.Repeat([]byte{0x42}, 6), "valid", "invalid", "verified", "ik_ck"},
		{"absent attributes", 16, false, false, false, nil, nil, "absent", "absent", "verified", "ik_ck"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, scenario.resOctets), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
			keys := referenceAKAKeys(provider, scenario.reverse)
			request := referenceChallenge(keys[16:32], false)[:48:48]
			if scenario.checkcode != nil {
				request = append(request, 134, byte((len(scenario.checkcode)+2)/4))
				request = append(request, scenario.checkcode...)
			}
			if scenario.bidding != nil {
				request = append(request, 136, byte((len(scenario.bidding)+2)/4))
				request = append(request, scenario.bidding...)
			}
			request = append(request, 11, 5, 0, 0)
			request = append(request, make([]byte, 16)...)
			binary.BigEndian.PutUint16(request[2:4], uint16(len(request)))
			mac := hmac.New(sha1.New, keys[16:32])
			mac.Write(request)
			copy(request[len(request)-16:], mac.Sum(nil)[:16])
			if scenario.tampered {
				request[len(request)-1] ^= 1
			}
			original := bytes.Clone(request)
			log, output := diagnosticLogger()
			sess := NewSession(&Config{SIM: provider, DisableEAPMACValidation: scenario.skipped}, log)

			payloads, err := sess.handleEAP(request)

			if !bytes.Equal(request, original) || provider.calls != 1 {
				t.Fatal("metadata changed input/SIM calls")
			}
			events := structureEvents(t, output)
			wantCount := 3
			if scenario.macStatus == "invalid" {
				wantCount = 2
			}
			if len(events) != wantCount {
				t.Fatalf("structure event count=%d want=%d", len(events), wantCount)
			}
			incoming, verification := events[0], events[1]
			if incoming.Phase != "request" || incoming.CheckcodeStatus != scenario.checkStatus || incoming.BiddingStatus != scenario.biddingStatus {
				t.Fatal("request structure status mismatch")
			}
			if scenario.checkStatus == "valid" {
				if incoming.CheckcodeOctets == nil || *incoming.CheckcodeOctets != len(scenario.checkcode)-2 || incoming.CheckcodeEmpty == nil || *incoming.CheckcodeEmpty != (len(scenario.checkcode) == 2) {
					t.Fatal("CHECKCODE shape mismatch")
				}
			} else if incoming.CheckcodeOctets != nil || incoming.CheckcodeEmpty != nil {
				t.Fatal("unvalidated CHECKCODE metadata emitted")
			}
			if scenario.biddingStatus == "valid" {
				if incoming.BiddingD == nil || *incoming.BiddingD != (scenario.bidding[0]&0x80 != 0) {
					t.Fatal("D bit not high bit of two-byte Value")
				}
			} else if incoming.BiddingD != nil {
				t.Fatal("unvalidated BIDDING bit emitted")
			}
			if verification.Phase != "request_mac" || verification.MACStatus != scenario.macStatus || verification.Verified != (scenario.macStatus == "verified") || verification.DerivationOrder != scenario.order {
				t.Fatal("actual MAC branch not recorded")
			}
			assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik, bytes.Repeat([]byte{0x51}, 20))
			if scenario.macStatus == "invalid" {
				if err == nil || len(payloads) != 0 || sess.MSK != nil {
					t.Fatal("MAC failure behavior changed")
				}
				return
			}
			if err != nil || len(payloads) != 1 {
				t.Fatal("existing successful path changed")
			}
			if scenario.skipped {
				keys = referenceAKAKeys(provider, false)
			}
			if !bytes.Equal(payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, referenceResponse(provider.res, keys[16:32], false)) {
				t.Fatal("response differs from independent golden encoding")
			}
			outgoing := events[2]
			if outgoing.Phase != "response" || outgoing.ParseError != "" || outgoing.RESOctets == nil || *outgoing.RESOctets != scenario.resOctets || outgoing.RESBits == nil || *outgoing.RESBits != scenario.resOctets*8 || outgoing.PaddingZero == nil || !*outgoing.PaddingZero || outgoing.IdentifierMatches == nil || !*outgoing.IdentifierMatches || outgoing.LocalMACValid == nil || !*outgoing.LocalMACValid {
				t.Fatal("response structural check mismatch")
			}
		})
	}
}
