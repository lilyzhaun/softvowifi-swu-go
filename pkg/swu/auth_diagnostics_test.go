package swu

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ikeAuthMetadataEvent struct {
	Message                string                `json:"msg"`
	Direction              string                `json:"direction"`
	Phase                  string                `json:"phase"`
	ParsedPayloadTypes     []int                 `json:"parsed_payload_types"`
	ParsedPayloadCount     int                   `json:"parsed_payload_count"`
	ParsedPayloadTruncated bool                  `json:"parsed_payload_types_truncated"`
	Notifications          []ikeAuthNotifyRecord `json:"notifications"`
	NotificationCount      int                   `json:"notification_count"`
	NotificationsTruncated bool                  `json:"notifications_truncated"`
	ProtectedPacketDecoded bool                  `json:"protected_packet_decoded"`
}

const (
	notifySecret = "PRIVATE-NOTIFY-IDENTITY-SENTINEL-LONG-SECRET-VALUE"
	imeiSecret   = "999999999999999"
	idSecret     = "PRIVATE-IDR-IDENTITY-SENTINEL"
)

func debugDiagnosticLogger() (*zap.Logger, *bytes.Buffer) {
	output := new(bytes.Buffer)
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(zapcore.AddSync(output)), zapcore.DebugLevel)
	return zap.New(core), output
}

func authMetadataEvents(t *testing.T, output *bytes.Buffer) []ikeAuthMetadataEvent {
	t.Helper()
	var events []ikeAuthMetadataEvent
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var event ikeAuthMetadataEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.Message == "IKE_AUTH metadata" {
			events = append(events, event)
		}
	}
}

func assertAuthMetadataWhitelist(t *testing.T, output *bytes.Buffer) {
	t.Helper()
	allowed := map[string]struct{}{
		"level": {}, "ts": {}, "msg": {},
		"direction": {}, "phase": {},
		"parsed_payload_types": {}, "parsed_payload_count": {}, "parsed_payload_types_truncated": {},
		"notifications": {}, "notification_count": {}, "notifications_truncated": {},
		"protected_packet_decoded": {},
	}
	nested := map[string]struct{}{"type": {}, "protocol": {}, "spi_length": {}, "data_length": {}}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var raw map[string]json.RawMessage
		err := decoder.Decode(&raw)
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if string(raw["msg"]) != `"IKE_AUTH metadata"` {
			continue
		}
		for key := range raw {
			if _, ok := allowed[key]; !ok {
				t.Fatalf("unwhitelisted metadata field %s", key)
			}
		}
		var records []map[string]json.RawMessage
		if err := json.Unmarshal(raw["notifications"], &records); err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			for key := range record {
				if _, ok := nested[key]; !ok {
					t.Fatalf("unwhitelisted notify field %s", key)
				}
			}
		}
	}
}

func Test_IKEAuthMetadata_whenFinalParserOmitsNotifyBytes(t *testing.T) {
	secret := []byte(notifySecret)
	log, output := debugDiagnosticLogger()
	sess := NewSession(&Config{}, log)
	enc, err := crypto.GetEncrypterWithKeyLen(12, 256)
	if err != nil {
		t.Fatal(err)
	}
	integ, err := crypto.GetIntegrityAlgorithm(12)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	mac := bytes.Repeat([]byte{7}, 32)
	sess.EncAlg, sess.IntegAlg = enc, integ
	sess.SPIr = 4321
	sess.PRFAlg = crypto.PRF_HMAC_SHA2_256
	sess.Keys = &ikev2.IKESAKeys{SK_ei: key, SK_er: key, SK_ai: mac, SK_ar: mac, SK_pr: bytes.Repeat([]byte{3}, 32)}
	sess.MSK = []byte("0123456789abcdef0123456789abcdef")
	sess.ni = []byte("initiator-nonce-32-bytes-value!")
	sess.saInitResp = []byte("real-message-2-sa-init-response")
	idr := &ikev2.EncryptedPayloadID{IDType: ikev2.ID_FQDN, IDData: []byte(idSecret)}
	idrBody, err := idr.Encode()
	if err != nil {
		t.Fatal(err)
	}
	authData := independentResponderAUTH(sess.MSK, sess.Keys.SK_pr, idrBody, sess.saInitResp, sess.ni)
	raw := encodePeerPacket(t, sess, []ikev2.Payload{
		idr,
		&ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: authData},
		&ikev2.EncryptedPayloadNotify{ProtocolID: ikev2.ProtoIKE, NotifyType: 41101, NotifyData: secret},
	}, ikev2.IKE_AUTH, 1, true)
	_ = sess.handleIKEAuthFinalResp(raw)
	events := authMetadataEvents(t, output)
	if len(events) != 1 || events[0].Phase != "final" || events[0].Direction != "received" || !events[0].ProtectedPacketDecoded {
		t.Fatalf("final metadata missing: %+v", events)
	}
	if !reflect.DeepEqual(events[0].ParsedPayloadTypes, []int{36, 39, 41}) || events[0].NotificationCount != 1 || events[0].Notifications[0].Type != 41101 || events[0].Notifications[0].DataLength != len(secret) {
		t.Fatalf("final parsed types incorrect: %+v", events[0])
	}
	if bytes.Contains(output.Bytes(), []byte(`"dataHex"`)) || bytes.Contains(output.Bytes(), []byte(`"digits"`)) {
		t.Fatal("legacy raw notify/IMEI fields still present")
	}
	assertAuthMetadataWhitelist(t, output)
	assertDiagnosticPrivacy(t, output, secret, []byte(idSecret))
}

func Test_DeviceIdentityResponse_whenLogsOmitDigits(t *testing.T) {
	log, output := diagnosticLogger()
	sess := NewSession(&Config{IMEI: imeiSecret}, log)
	payloads, err := sess.buildDeviceIdentityResponse(0x01)
	if err != nil || len(payloads) != 1 {
		t.Fatal("DEVICE_IDENTITY response construction changed")
	}
	notify := payloads[0].(*ikev2.EncryptedPayloadNotify)
	if notify.NotifyType != ikev2.DEVICE_IDENTITY || len(notify.NotifyData) == 0 {
		t.Fatal("response payload changed")
	}
	if bytes.Contains(output.Bytes(), []byte(`"digits"`)) || bytes.Contains(output.Bytes(), []byte(imeiSecret)) || bytes.Contains(output.Bytes(), []byte(imeiSecret+"F")) {
		t.Fatal("IMEI digits leaked")
	}
}

func Test_IKEAuthMetadata_whenRecordsAreBoundedAndWhitelisted(t *testing.T) {
	secret := bytes.Repeat([]byte(notifySecret), 8)
	log, output := diagnosticLogger()
	sess := NewSession(&Config{}, log)
	payloads := []ikev2.Payload{&ikev2.EncryptedPayloadID{IDData: []byte(idSecret), IDType: ikev2.ID_FQDN}}
	for index := 0; index < 65; index++ {
		data := []byte(nil)
		if index == 0 {
			data = secret
		}
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: ikev2.ProtoIKE,
			NotifyType: uint16(2000 - index),
			NotifyData: data,
		})
	}
	sess.logIKEAuthMetadata(ikeAuthPhaseEAPLoop, payloads)
	events := authMetadataEvents(t, output)
	if len(events) != 1 {
		t.Fatal("expected one metadata event")
	}
	event := events[0]
	if event.ParsedPayloadCount != 66 || !event.ParsedPayloadTruncated || len(event.ParsedPayloadTypes) != 64 || event.ParsedPayloadTypes[0] != 36 {
		t.Fatalf("payload bound/order incorrect: %+v", event)
	}
	if event.NotificationCount != 65 || !event.NotificationsTruncated || len(event.Notifications) != 64 || event.Notifications[0].Type != 2000 || event.Notifications[63].Type != 1937 {
		t.Fatalf("notify bound/order sorted or truncated wrong: %+v", event.Notifications)
	}
	if event.Notifications[0].DataLength != len(secret) || event.Notifications[1].Type != 1999 {
		t.Fatal("wire order of notify types was not preserved")
	}
	assertAuthMetadataWhitelist(t, output)
	assertDiagnosticPrivacy(t, output, secret, []byte(idSecret))
}
