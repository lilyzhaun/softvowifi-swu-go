package swu

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func Test_EAPOnlyAUTH1ChangesOnlyProtocolID_whenIdentityAndSPIAreFixed(t *testing.T) {
	// Given: captured at 01ea6072, synthetic vectorSIM identity and child SPI 0x12345678.
	fixture, err := os.ReadFile("testdata/eap_only_auth1_before.hex")
	if err != nil {
		t.Fatal(err)
	}
	before := referenceHex(t, strings.TrimSpace(string(fixture)))
	protocolOffset := len(before) - 12
	if !bytes.Equal(before[protocolOffset-4:], []byte{41, 0, 0, 8, 1, 0, 0x40, 0x21, 0, 0, 0, 8, 0, 0, 0x40, 0}) {
		t.Fatal("baseline must end with historical EAP_ONLY and unchanged INITIAL_CONTACT")
	}
	want := bytes.Clone(before)
	// RFC 5998 section 3: Protocol ID and SPI size zero; no SPI or additional data.
	want[protocolOffset] = 0
	log, _ := diagnosticLogger()
	session := NewSession(&Config{SIM: &vectorSIM{}, APN: "ims"}, log)
	session.childSPI = 0x12345678

	// When
	payloads, err := session.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	packet := &ikev2.IKEPacket{Header: &ikev2.IKEHeader{}, Payloads: payloads}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if !bytes.Equal(raw[28:], want) {
		t.Fatal("AUTH1 plaintext must equal baseline except EAP_ONLY Protocol ID 1 -> 0")
	}
	assertAKAWireInitial(t, parseAKAWirePayloads(t, 35, raw[28:]))
	t.Logf("all %d plaintext bytes equal baseline except Protocol ID at offset %d", len(want), protocolOffset)
}
