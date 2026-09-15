package swu

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const syntheticInitialIMEI = "123456789012345"

const syntheticInitialType2Before = "2400003e0300000030303031303130303030303030303031406e61692e6570632e6d6e633030312e6d63633030312e336770706e6574776f726b2e6f72672f00000b02000000696d73210000240100000000010000000300000014000000080000000a000000150000400600002c0000bc0200002001030402123456780300000c01000014800e010000000008050000000200002002030402123456780300000c01000014800e008000000008050000000200002803030403123456780300000c0100000c800e0100030000080300000c00000008050000000200002804030403123456780300000c0100000c800e0080030000080300000c00000008050000000000002805030403123456780300000c0100000c800e0080030000080300000200000008050000002d00004002000000070000100000ffff00000000ffffffff080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff2900004002000000070000100000ffff00000000ffffffff080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff29000008000040212900000800004000000000130000a08d00090221436587092143f5"

func initialIdentityBaseline(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile("testdata/eap_only_auth1_before.hex")
	if err != nil {
		t.Fatal(err)
	}
	baseline := referenceHex(t, strings.TrimSpace(string(fixture)))
	baseline[len(baseline)-12] = 0
	return baseline
}

func encodeInitialIdentityPacket(t *testing.T, payloads []ikev2.Payload) []byte {
	t.Helper()
	packet := &ikev2.IKEPacket{Header: &ikev2.IKEHeader{}, Payloads: payloads}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw[28:]
}

func Test_InitialDeviceIdentity_whenConfiguredChangesOnlyAppendedNotify(t *testing.T) {
	// Given: fixed synthetic identity/SPI; target class selects type 1 for 15 digits.
	baseline := initialIdentityBaseline(t)
	output := new(bytes.Buffer)
	log := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(output), zapcore.DebugLevel))
	sess := NewSession(&Config{SIM: &vectorSIM{}, APN: "ims", IMEI: syntheticInitialIMEI}, log)
	sess.childSPI = 0x12345678
	wantNotify := referenceHex(t, "000000130000a08d00090121436587092143f5")

	// When
	payloads, err := sess.buildIKEAuthInitialDevicePayloads()
	if err != nil {
		t.Fatal(err)
	}
	plain := encodeInitialIdentityPacket(t, payloads)

	// Then: parse the chain independently, remove only 41101, restore the former terminator.
	parsed := parseAKAWirePayloads(t, 35, plain)
	if len(parsed) != 9 || parsed[8].kind != 41 || !bytes.Equal(parsed[8].body, wantNotify[4:]) {
		t.Fatal("15-digit IMEI must use identity type 1, not IMEISV type 2")
	}
	assertAKAWireInitial(t, parsed[:8])
	if len(plain) != 460 || !bytes.Equal(plain[441:], wantNotify) {
		t.Fatal("only one 19-byte notify may be appended")
	}
	restored := bytes.Clone(plain[:441])
	if restored[433] != 41 {
		t.Fatal("INITIAL_CONTACT must link to the appended notification")
	}
	restored[433] = 0
	if !bytes.Equal(restored, baseline) {
		t.Fatal("all 441 original plaintext bytes must remain identical after restoring the chain")
	}
	assertDiagnosticPrivacy(t, output, []byte(syntheticInitialIMEI), wantNotify[11:], wantNotify[8:])
	before := referenceHex(t, syntheticInitialType2Before)
	if len(before) != len(plain) || before[451] != 2 || plain[451] != 1 {
		t.Fatal("captured 460-byte baseline must differ at identity type 2 -> 1")
	}
	for offset := range before {
		if offset != 451 && before[offset] != plain[offset] {
			t.Fatalf("unexpected change outside identity type at plaintext offset %d", offset)
		}
	}
	t.Log("460-byte A/B: only plaintext offset 451 changed 2 -> 1; original 441 bytes preserved")
}

func Test_InitialDeviceIdentity_whenEmptyPreservesLegacyBytes(t *testing.T) {
	// Given
	log, _ := diagnosticLogger()
	sess := NewSession(&Config{SIM: &vectorSIM{}, APN: "ims"}, log)
	sess.childSPI = 0x12345678

	// When
	payloads, err := sess.buildIKEAuthInitialDevicePayloads()
	// Then
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodeInitialIdentityPacket(t, payloads), initialIdentityBaseline(t)) {
		t.Fatal("missing configured IMEI must preserve the legacy request, not invent an identity")
	}
}

func Test_InitialDeviceIdentity_whenInvalidRejectsBeforeSIMAccess(t *testing.T) {
	for _, scenario := range []struct{ name, imei string }{
		{"short", "12345678901234"},
		{"long", "1234567890123456"},
		{"zero", "000000000000000"},
		{"letter", "12345678901234a"},
		{"padding", "12345678901234F"},
		{"space", "12345678901234 "},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			// Given
			provider := &diagnosticSIM{}
			log, output := diagnosticLogger()
			sess := NewSession(&Config{SIM: provider, IMEI: scenario.imei}, log)

			// When
			payloads, err := sess.buildIKEAuthInitialDevicePayloads()

			// Then
			if !errors.Is(err, errInitialDeviceIdentity) || payloads != nil {
				t.Fatal("invalid configured identity must return only the fixed error")
			}
			if strings.Contains(err.Error(), scenario.imei) || provider.imsiCalls != 0 || provider.akaCalls != 0 || sess.childSPI != 0 {
				t.Fatal("invalid identity leaked or triggered payload-building side effects")
			}
			assertDiagnosticPrivacy(t, output, []byte(scenario.imei))
		})
	}
}

func Test_InitialDeviceIdentity_whenResumeBuilderUsedKeepsOriginalRequest(t *testing.T) {
	// Given: sendIkeAuthChildless continues to use the shared original builder.
	log, _ := diagnosticLogger()
	sess := NewSession(&Config{SIM: &vectorSIM{}, APN: "ims", IMEI: syntheticInitialIMEI}, log)
	sess.childSPI = 0x12345678

	// When
	payloads, err := sess.buildIKEAuthInitPayloads()
	// Then
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodeInitialIdentityPacket(t, payloads), initialIdentityBaseline(t)) {
		t.Fatal("resume builder must keep all original bytes even when IMEI is configured")
	}
}

func Test_InitialDeviceIdentity_whenFinalAUTHBuiltKeepsBytes(t *testing.T) {
	// Given: fixed synthetic signing inputs, differing only in configured IMEI.
	log, _ := diagnosticLogger()
	sess := NewSession(&Config{SIM: &vectorSIM{}, APN: "ims"}, log)
	prf, err := crypto.GetPRF(5)
	if err != nil {
		t.Fatal(err)
	}
	sess.PRFAlg = prf
	sess.MSK = bytes.Repeat([]byte{1}, 64)
	sess.Keys = &ikev2.IKESAKeys{SK_pi: bytes.Repeat([]byte{2}, 32)}
	sess.msgBuffer = []byte("synthetic SA_INIT")
	sess.nr = bytes.Repeat([]byte{3}, 32)
	if _, err := sess.buildIKEAuthInitPayloads(); err != nil {
		t.Fatal(err)
	}
	baseline, err := sess.buildIKEAuthFinalPayloads()
	if err != nil {
		t.Fatal(err)
	}
	sess.cfg.IMEI = syntheticInitialIMEI

	// When
	payloads, err := sess.buildIKEAuthFinalPayloads()
	// Then
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 || payloads[0].Type() != ikev2.AUTH || !bytes.Equal(encodeInitialIdentityPacket(t, payloads), encodeInitialIdentityPacket(t, baseline)) {
		t.Fatal("final AUTH must remain byte-identical without an extra notification")
	}
}
