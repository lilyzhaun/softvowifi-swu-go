package ikev2

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func childStructureSA(t *testing.T) []byte {
	t.Helper()
	p := CreateMultiProposalESP([]byte{1, 2, 3, 4})[2]
	raw, err := (&EncryptedPayloadSA{Proposals: []*Proposal{p}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestChildSAParserRequiresClosedProposalAndTransformChains(t *testing.T) {
	for _, variant := range []string{"proposal tail", "transform tail", "too few transforms", "early last transform", "bad proposal link", "bad transform link", "missing last transform", "empty SA"} {
		t.Run(variant, func(t *testing.T) {
			raw := bytes.Clone(childStructureSA(t))
			last := len(raw) - 8
			switch variant {
			case "proposal tail":
				raw = append(raw, 0)
			case "transform tail":
				raw = append(raw, 0)
				binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			case "too few transforms":
				raw[7]--
			case "early last transform":
				raw[12] = 0
			case "bad proposal link":
				raw[0] = 1
			case "bad transform link":
				raw[12] = 2
			case "missing last transform":
				raw[last] = 3
			case "empty SA":
				raw = nil
			}
			if _, err := DecodePayloadSA(raw); err == nil {
				t.Fatal("malformed Child proposal/transform chain accepted")
			}
		})
	}
	if _, err := DecodePayloadSA(childStructureSA(t)); err != nil {
		t.Fatal("legal complete Child selection rejected")
	}
}

func TestChildTSParserRejectsUnaccountedSelectorBytes(t *testing.T) {
	p := &EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: []*TrafficSelector{NewTrafficSelectorIPV4(net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 10), 0, 65535)}}
	raw, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), append([]byte{0}, raw[1:]...)} {
		if _, err := DecodePayloadTS(bad, true); err == nil {
			t.Fatal("unaccounted TS selector bytes accepted")
		}
	}
	if _, err := DecodePayloadTS(raw, true); err != nil {
		t.Fatal(err)
	}
}

func TestChildCPReservedBitDoesNotChangeTLVFormat(t *testing.T) {
	// RFC7296 3.15.1: this high bit is reserved/ignored, not the SA AF bit.
	raw := []byte{CFG_REPLY, 0, 0, 0, 0x80, 1, 0, 4, 192, 0, 2, 10}
	parsed, err := DecodePayloadCP(raw)
	if err != nil || len(parsed.Attributes) != 1 || parsed.Attributes[0].Type != INTERNAL_IP4_ADDRESS || !bytes.Equal(parsed.Attributes[0].Value, raw[8:]) {
		t.Fatalf("reserved CP bit misparsed standard TLV: %v", err)
	}
}
