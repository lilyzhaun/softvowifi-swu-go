package swu

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type diagnosticEvent struct {
	Message    string `json:"msg"`
	Direction  string `json:"direction"`
	Code       int    `json:"code"`
	Type       int    `json:"type"`
	Subtype    int    `json:"subtype"`
	AttrTypes  []int  `json:"attr_types"`
	AttrCount  int    `json:"attr_count"`
	Truncated  bool   `json:"attr_types_truncated"`
	ParseError string `json:"parse_error"`
	Terminal   string `json:"terminal"`
	Phase      string `json:"phase"`
	Invoked    bool   `json:"invoked"`
	Result     string `json:"result"`
}

func diagnosticLogger() (*zap.Logger, *bytes.Buffer) {
	output := new(bytes.Buffer)
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(zapcore.AddSync(output)), zapcore.InfoLevel)
	return zap.New(core), output
}

func diagnosticEvents(t *testing.T, output *bytes.Buffer) []diagnosticEvent {
	t.Helper()
	var events []diagnosticEvent
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var event diagnosticEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.Message == "EAP stage" || event.Message == "SIM AKA" {
			events = append(events, event)
		}
	}
}

func assertDiagnosticPrivacy(t *testing.T, output *bytes.Buffer, markers ...[]byte) {
	t.Helper()
	for _, marker := range markers {
		for _, encoded := range []string{string(marker), hex.EncodeToString(marker), base64.StdEncoding.EncodeToString(marker)} {
			if bytes.Contains(output.Bytes(), []byte(encoded)) {
				t.Error("serialized log contains synthetic secret")
			}
		}
	}
	for _, key := range []string{"identifier", "nai", "reauthID", "NextReauthID", "data", "error"} {
		if bytes.Contains(output.Bytes(), []byte(`"`+key+`":`)) {
			t.Errorf("forbidden log field %s", key)
		}
	}
}

func Test_EAPDiagnostics_whenReceived(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		packet   eap.EAPPacket
		terminal string
	}{
		{"success", eap.EAPPacket{Code: 3}, "eap_success"},
		{"failure", eap.EAPPacket{Code: 4}, "eap_failure"},
		{"unknown method", eap.EAPPacket{Code: 1, Type: 99, Data: []byte("PRIVATE-UNKNOWN-DATA")}, ""},
		{"AKA identity missing request attribute", eap.EAPPacket{Code: 1, Type: 23, Subtype: 5}, ""},
		{"AKA prime identity unchanged", eap.EAPPacket{Code: 1, Type: 50, Subtype: 5}, ""},
		{"reauth unchanged", eap.EAPPacket{Code: 1, Type: 23, Subtype: 13}, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			log, output := diagnosticLogger()
			sess := NewSession(&Config{}, log)
			response, err := sess.handleEAP(scenario.packet.Encode())
			if scenario.packet.Code == 3 {
				if err != nil || response != nil {
					t.Fatal("success behavior changed")
				}
			} else if scenario.packet.Type == 23 && scenario.packet.Subtype == 5 {
				if err != nil || len(response) != 1 {
					t.Fatal("malformed identity must produce client error")
				}
				packet, ok := response[0].(*ikev2.EncryptedPayloadEAP)
				if !ok || !bytes.Equal(packet.EAPMessage, []byte{2, 0, 0, 12, 23, 14, 0, 0, 22, 1, 0, 0}) {
					t.Fatal("malformed identity client error wire differs")
				}
			} else if err == nil {
				t.Fatal("existing rejection changed")
			}
			events := diagnosticEvents(t, output)
			if len(events) != 1 {
				t.Fatalf("diagnostic count = %d, want 1", len(events))
			}
			event := events[0]
			if event.Direction != "received" || event.Code != int(scenario.packet.Code) || event.Type != int(scenario.packet.Type) || event.Subtype != int(scenario.packet.Subtype) || event.Terminal != scenario.terminal || event.ParseError != "" {
				t.Fatalf("incorrect public metadata: %+v", event)
			}
			assertDiagnosticPrivacy(t, output, []byte("PRIVATE-UNKNOWN-DATA"))
		})
	}
}

func Test_EAPDiagnostics_whenIdentityUsesPseudonym(t *testing.T) {
	secret := []byte("PRIVATE-PSEUDONYM@invalid")
	log, output := diagnosticLogger()
	provider := &diagnosticSIM{}
	sess := NewSession(&Config{SIM: provider, FastReauthID: string(secret), FastReauthMK: bytes.Repeat([]byte{7}, 20)}, log)
	if _, err := sess.buildIKEAuthInitPayloads(); err != nil {
		t.Fatal(err)
	}
	payloads, err := sess.handleEAP((&eap.EAPPacket{Code: 1, Identifier: 91, Type: 1, Data: []byte("PRIVATE-IDENTITY-REQUEST")}).Encode())
	if err != nil || len(payloads) != 1 {
		t.Fatal("identity response failed")
	}
	if provider.imsiCalls != 0 || provider.akaCalls != 0 {
		t.Fatal("diagnostics invoked SIM for cached identity")
	}
	assertDiagnosticPrivacy(t, output, secret, []byte("PRIVATE-IDENTITY-REQUEST"))
	if len(diagnosticEvents(t, output)) != 1 {
		t.Fatal("missing received identity diagnostic")
	}
}

func Test_EAPDiagnostics_whenSentPayloadsContainSecrets(t *testing.T) {
	for _, method := range []uint8{23, 50} {
		log, output := diagnosticLogger()
		sess := NewSession(&Config{}, log)
		marker := []byte("PRIVATE-ALL-ATTRIBUTE-VALUES")
		var data []byte
		for _, attrType := range []uint8{133, 132, 14, 11, 3, 250, 133} {
			data = append(data, (&eap.Attribute{Type: attrType, Value: marker}).Encode()...)
		}
		raw := (&eap.EAPPacket{Code: 2, Identifier: 231, Type: method, Subtype: 1, Data: data}).Encode()
		original := bytes.Clone(raw)
		sess.logSentEAP([]ikev2.Payload{
			&ikev2.EncryptedPayloadID{IDData: marker},
			&ikev2.EncryptedPayloadEAP{EAPMessage: raw},
		})
		events := diagnosticEvents(t, output)
		if len(events) != 1 || events[0].Direction != "send_attempt" || events[0].Code != 2 || events[0].Type != int(method) || events[0].Subtype != 1 || !reflect.DeepEqual(events[0].AttrTypes, []int{3, 11, 14, 132, 133, 250}) || events[0].AttrCount != 6 || events[0].Truncated {
			t.Fatal("sent public metadata changed")
		}
		if !bytes.Equal(raw, original) {
			t.Fatal("diagnostics mutated response bytes")
		}
		assertDiagnosticPrivacy(t, output, marker)
	}
}

func Test_EAPDiagnostics_whenMalformedOrBounded(t *testing.T) {
	for _, raw := range [][]byte{nil, {1}, {1, 2, 0, 9}, {1, 2, 0, 3}, {1, 2, 0, 4}, {1, 2, 0, 6, 23, 5}, {1, 2, 0, 7, 50, 1, 0}} {
		log, output := diagnosticLogger()
		sess := NewSession(&Config{}, log)
		_, _ = sess.handleEAP(raw)
		events := diagnosticEvents(t, output)
		if len(events) != 1 || events[0].ParseError != "invalid_packet" {
			t.Fatal("short frame lacks fixed parse error")
		}
	}
	for _, data := range [][]byte{{11, 0, 0, 0}, {11, 2, 0, 0}, {11}} {
		log, output := diagnosticLogger()
		sess := NewSession(&Config{}, log)
		_, _ = sess.handleEAP((&eap.EAPPacket{Code: 1, Type: 23, Subtype: 1, Data: data}).Encode())
		events := diagnosticEvents(t, output)
		if len(events) != 1 || events[0].ParseError != "invalid_attributes" || len(events[0].AttrTypes) != 0 {
			t.Fatal("malformed attributes lack fixed error")
		}
	}
	var attrs []byte
	for attrType := 70; attrType >= 1; attrType-- {
		attrs = append(attrs, byte(attrType), 1, 0, 0)
	}
	log, output := diagnosticLogger()
	sess := NewSession(&Config{}, log)
	_, _ = sess.handleEAP((&eap.EAPPacket{Code: 1, Type: 50, Subtype: 5, Data: attrs}).Encode())
	events := diagnosticEvents(t, output)
	want := make([]int, 64)
	for index := range want {
		want[index] = index + 1
	}
	if len(events) != 1 || !reflect.DeepEqual(events[0].AttrTypes, want) || events[0].AttrCount != 70 || !events[0].Truncated {
		t.Fatal("attribute IDs not sorted and explicitly bounded")
	}
}
