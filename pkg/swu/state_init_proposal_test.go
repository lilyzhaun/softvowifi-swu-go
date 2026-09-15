package swu

import (
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func Test_buildIKESAInitPacket_emitsFourCompleteProposals_whenLayoutDefault(t *testing.T) {
	cases := []string{"", ikev2.ProposalLayoutMultipleComplete}
	for _, layout := range cases {
		t.Run(layout, func(t *testing.T) {
			// Given
			sess := newInitTestSession(layout)

			// When
			raw, err := sess.buildIKESAInitPacket()
			// Then
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			sa, ke, notifies := decodeInitSA(t, raw)
			if len(sa.Proposals) != 4 {
				t.Fatalf("proposals = %d, want 4", len(sa.Proposals))
			}
			for i, prop := range sa.Proposals {
				if len(prop.Transforms) != 4 {
					t.Fatalf("proposal %d transforms = %d, want 4", i+1, len(prop.Transforms))
				}
			}
			assertInitKEAndNotifies(t, ke, notifies)
		})
	}
}

func Test_buildIKESAInitPacket_emitsSingleCombinedProposal_whenLayoutSingleCombined(t *testing.T) {
	// Given
	sess := newInitTestSession(ikev2.ProposalLayoutSingleCombined)

	// When
	raw, err := sess.buildIKESAInitPacket()
	// Then
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sa, ke, notifies := decodeInitSA(t, raw)
	if len(sa.Proposals) != 1 {
		t.Fatalf("proposals = %d, want 1", len(sa.Proposals))
	}
	got := sa.Proposals[0].Transforms
	want := []struct {
		typ    ikev2.TransformType
		id     ikev2.AlgorithmType
		keyLen uint16
	}{
		{ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128},
		{ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256},
		{ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0},
		{ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_384_192, 0},
		{ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA1_96, 0},
		{ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_256, 0},
		{ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA2_384, 0},
		{ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA1, 0},
		{ikev2.TransformTypePRF, ikev2.PRF_AES128_XCBC, 0},
		{ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0},
	}
	if len(got) != len(want) {
		t.Fatalf("transforms = %d, want %d", len(got), len(want))
	}
	for i, xf := range got {
		var keyLen uint16
		if len(xf.Attributes) > 0 {
			keyLen = xf.Attributes[0].Val
		}
		if xf.Type != want[i].typ || xf.ID != want[i].id || keyLen != want[i].keyLen {
			t.Fatalf("transform[%d] = type=%d id=%d key=%d, want type=%d id=%d key=%d",
				i, xf.Type, xf.ID, keyLen, want[i].typ, want[i].id, want[i].keyLen)
		}
	}
	assertInitKEAndNotifies(t, ke, notifies)
}

func newInitTestSession(layout string) *Session {
	return NewSession(&Config{
		EpDGAddr:          "192.0.2.2",
		EpDGPort:          500,
		LocalAddr:         "192.0.2.1",
		LocalPort:         500,
		IKEProposalLayout: layout,
	}, zap.NewNop())
}

func decodeInitSA(t *testing.T, raw []byte) (*ikev2.EncryptedPayloadSA, *ikev2.EncryptedPayloadKE, []*ikev2.EncryptedPayloadNotify) {
	t.Helper()
	packet, err := ikev2.DecodePacket(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var sa *ikev2.EncryptedPayloadSA
	var ke *ikev2.EncryptedPayloadKE
	var notifies []*ikev2.EncryptedPayloadNotify
	for _, p := range packet.Payloads {
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			sa = v
		case *ikev2.EncryptedPayloadKE:
			ke = v
		case *ikev2.EncryptedPayloadNotify:
			notifies = append(notifies, v)
		}
	}
	if sa == nil {
		t.Fatal("missing SA payload")
	}
	if ke == nil {
		t.Fatal("missing KE payload")
	}
	return sa, ke, notifies
}

func assertInitKEAndNotifies(t *testing.T, ke *ikev2.EncryptedPayloadKE, notifies []*ikev2.EncryptedPayloadNotify) {
	t.Helper()
	if ke.DHGroup != ikev2.MODP_2048_bit {
		t.Fatalf("KE DHGroup = %d, want 14", ke.DHGroup)
	}
	var sawFrag, sawNAT bool
	for _, n := range notifies {
		if n.ProtocolID != 0 {
			t.Fatalf("notify type %d ProtocolID = %d, want 0", n.NotifyType, n.ProtocolID)
		}
		switch n.NotifyType {
		case ikev2.IKEV2_FRAGMENTATION_SUPPORTED:
			sawFrag = true
		case ikev2.NAT_DETECTION_SOURCE_IP, ikev2.NAT_DETECTION_DESTINATION_IP:
			sawNAT = true
		}
	}
	if !sawFrag {
		t.Fatal("missing FRAG notify")
	}
	if !sawNAT {
		t.Fatal("missing NAT notify")
	}
}
