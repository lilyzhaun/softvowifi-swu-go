package swu

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// JSON keeps this direct wire regression compilable before the policy exists.
func TestR8ChildPFSRequestedPolicyReachesActualEncryptedRekey(t *testing.T) {
	s, transport := childRekeySession(t)
	if err := json.Unmarshal([]byte(`{"ChildPFSGroup":14}`), s.cfg); err != nil {
		t.Fatal("invalid synthetic Child PFS fixture")
	}
	oldIKEPublic := append([]byte(nil), s.DH.PublicKeyBytes()...)
	done := make(chan error, 1)
	go func() { done <- s.rekeyChildSA(newRekeyKernel()) }()
	var raw []byte
	select {
	case raw = <-transport.sent:
	case <-s.ctx.Done():
		t.Fatal("actual encrypted Child rekey request not reached")
	}
	s.cancel()
	<-done
	header, err := ikev2.DecodeHeader(raw)
	if err != nil || header.ExchangeType != ikev2.CREATE_CHILD_SA || header.NextPayload != ikev2.SK {
		t.Fatal("did not receive actual protected CREATE_CHILD_SA")
	}
	parts := peerChildOpen(t, raw, s.Keys.SK_ei, s.Keys.SK_ai)
	ke := parts[byte(ikev2.KE)]
	if len(ke) != 260 || binary.BigEndian.Uint16(ke[:2]) != 14 {
		t.Fatalf("actual Child rekey KE length=%d, want fresh MODP14 payload", len(ke))
	}
	if bytes.Equal(ke[4:], oldIKEPublic) {
		t.Fatal("Child PFS reused the original IKE DH public key")
	}
	proposals := parts[byte(ikev2.SA)]
	if len(proposals) == 0 {
		t.Fatal("actual PFS request lost the complete ESP offer")
	}
	for offset := 0; offset < len(proposals); {
		if len(proposals)-offset < 8 {
			t.Fatal("short actual proposal header")
		}
		length := int(binary.BigEndian.Uint16(proposals[offset+2 : offset+4]))
		if length < 8 || length > len(proposals)-offset {
			t.Fatal("invalid actual proposal length")
		}
		proposal := proposals[offset : offset+length]
		found := false
		for cursor := 8 + int(proposal[6]); cursor < len(proposal); {
			if len(proposal)-cursor < 8 {
				t.Fatal("short actual transform header")
			}
			n := int(binary.BigEndian.Uint16(proposal[cursor+2 : cursor+4]))
			if n < 8 || n > len(proposal)-cursor {
				t.Fatal("invalid actual transform length")
			}
			if proposal[cursor+4] == byte(ikev2.TransformTypeDH) {
				if found || binary.BigEndian.Uint16(proposal[cursor+6:cursor+8]) != 14 {
					t.Fatal("duplicate or mismatched actual Child PFS transform")
				}
				found = true
			}
			cursor += n
		}
		if !found {
			t.Fatal("actual ESP proposal did not bind the Child KE group")
		}
		offset += length
	}
}
