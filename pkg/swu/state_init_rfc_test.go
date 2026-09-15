package swu

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func initRFCReservedWire(raw []byte) []byte {
	wire := bytes.Clone(raw)
	wire[17] = 0x21
	wire[19] |= ikev2.FlagVersion | 0xc7
	wire[29] |= 0x7f
	wire[33] = 0xff
	for offset := 40; offset < 76; offset += int(binary.BigEndian.Uint16(wire[offset+2 : offset+4])) {
		wire[offset+1], wire[offset+5] = 0xff, 0xff
	}
	return wire
}

func initUnknownNoncriticalWire(raw []byte) []byte {
	wire := bytes.Clone(raw[:28])
	wire[16] = 250
	wire = append(wire, raw[16], 0x7f, 0, 5, 0xab)
	wire = append(wire, raw[28:]...)
	binary.BigEndian.PutUint32(wire[24:28], uint32(len(wire)))
	return wire
}

func initUnknownCriticalWire(raw []byte) []byte {
	wire := initUnknownNoncriticalWire(raw)
	wire[29] |= 0x80
	return wire
}

func Test_InitRFCReservedFieldsAccepted_whenSelectionBound(t *testing.T) {
	cases := map[string]func([]byte){
		"minor":               func(raw []byte) { raw[17] = 0x2f },
		"V flag":              func(raw []byte) { raw[19] |= ikev2.FlagVersion },
		"reserved flags":      func(raw []byte) { raw[19] |= 0xc7 },
		"generic reserved":    func(raw []byte) { raw[29] |= 0x7f },
		"proposal reserved":   func(raw []byte) { raw[33] = 0xff },
		"transform reserved1": func(raw []byte) { raw[41] = 0xff },
		"transform reserved2": func(raw []byte) { raw[45] = 0xff },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sess, packet := initSelectionFixture(t)
			raw, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			mutate(raw)
			if err := sess.handleIKESAInitResp(raw, sess.msgBuffer); err != nil {
				t.Fatal(err)
			}
			if sess.Keys == nil {
				t.Fatal("missing keys for valid RFC response")
			}
		})
	}
}

func Test_InitRFCStructureRejected_whenReservedFieldsIgnored(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"unknown critical":             initUnknownCriticalWire,
		"known wrong exchange payload": func(raw []byte) []byte { raw = initUnknownNoncriticalWire(raw); raw[16] = byte(ikev2.AUTH); return raw },
		"unknown overrun":              func(raw []byte) []byte { raw = initUnknownNoncriticalWire(raw); raw[30] = 0xff; return raw },
		"proposal more without next":   func(raw []byte) []byte { raw[32] = 2; return raw },
		"proposal invalid terminal":    func(raw []byte) []byte { raw[32] = 1; return raw },
		"transform premature terminal": func(raw []byte) []byte { raw[40] = 0; return raw },
		"transform missing terminal":   func(raw []byte) []byte { raw[68] = 3; return raw },
		"hidden transform":             func(raw []byte) []byte { raw[39] = 3; return raw },
		"extra proposal hidden after terminal": func(raw []byte) []byte {
			wire := append(bytes.Clone(raw[:76]), raw[32:76]...)
			wire = append(wire, raw[76:]...)
			binary.BigEndian.PutUint16(wire[30:32], 92)
			binary.BigEndian.PutUint32(wire[24:28], uint32(len(wire)))
			return wire
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sess, packet := initSelectionFixture(t)
			raw, err := packet.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.handleIKESAInitResp(mutate(raw), sess.msgBuffer); err == nil {
				t.Fatal("accepted invalid structure")
			}
			if sess.SPIr != 0 || sess.Keys != nil || sess.PRFAlg != nil || len(sess.nr) != 0 || sess.fragmentationSupported || sess.natKeepaliveStarted {
				t.Fatal("invalid response mutated session")
			}
		})
	}
}

func Test_InitCookieSkipsUnknownNoncritical_whenHeaderMatches(t *testing.T) {
	sess, packet := initSelectionFixture(t)
	packet.Header.SPIr = 0
	packet.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{1}}}
	raw, err := packet.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.handleIKESAInitResp(initUnknownNoncriticalWire(raw), sess.msgBuffer); err != ErrCookieRequired {
		t.Fatalf("cookie: %v", err)
	}
}
