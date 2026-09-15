package ikev2

import "testing"

func Test_CreateIKEProposals_emitsFourCompleteSuites_whenMultipleComplete(t *testing.T) {
	cases := []string{"", ProposalLayoutMultipleComplete}
	for _, layout := range cases {
		t.Run(layout, func(t *testing.T) {
			// Given / When
			got := CreateIKEProposals(layout, nil)

			// Then
			assertMultipleCompleteIKE(t, got)
		})
	}
}

func Test_CreateIKEProposals_emitsSingleCombinedUnion_whenSingleCombined(t *testing.T) {
	// Given / When
	got := CreateIKEProposals(ProposalLayoutSingleCombined, nil)

	// Then
	assertSingleCombinedIKE(t, got)
}

func assertMultipleCompleteIKE(t *testing.T, proposals []*Proposal) {
	t.Helper()
	if len(proposals) != 4 {
		t.Fatalf("proposal count = %d, want 4", len(proposals))
	}
	want := [][]wantTransform{
		{
			{TransformTypeEncr, ENCR_AES_CBC, 128},
			{TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0},
			{TransformTypePRF, PRF_HMAC_SHA2_256, 0},
			{TransformTypeDH, MODP_2048_bit, 0},
		},
		{
			{TransformTypeEncr, ENCR_AES_CBC, 256},
			{TransformTypeInteg, AUTH_HMAC_SHA2_384_192, 0},
			{TransformTypePRF, PRF_HMAC_SHA2_384, 0},
			{TransformTypeDH, MODP_2048_bit, 0},
		},
		{
			{TransformTypeEncr, ENCR_AES_CBC, 128},
			{TransformTypeInteg, AUTH_HMAC_SHA1_96, 0},
			{TransformTypePRF, PRF_HMAC_SHA1, 0},
			{TransformTypeDH, MODP_2048_bit, 0},
		},
		{
			{TransformTypeEncr, ENCR_AES_CBC, 256},
			{TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0},
			{TransformTypePRF, PRF_HMAC_SHA2_256, 0},
			{TransformTypeDH, MODP_2048_bit, 0},
		},
	}
	for i, prop := range proposals {
		if len(prop.Transforms) != 4 {
			t.Fatalf("proposal %d transforms = %d, want 4", i+1, len(prop.Transforms))
		}
		assertTransforms(t, prop.Transforms, want[i])
	}
}

func assertSingleCombinedIKE(t *testing.T, proposals []*Proposal) {
	t.Helper()
	if len(proposals) != 1 {
		t.Fatalf("proposal count = %d, want 1", len(proposals))
	}
	want := []wantTransform{
		{TransformTypeEncr, ENCR_AES_CBC, 128},
		{TransformTypeEncr, ENCR_AES_CBC, 256},
		{TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0},
		{TransformTypeInteg, AUTH_HMAC_SHA2_384_192, 0},
		{TransformTypeInteg, AUTH_HMAC_SHA1_96, 0},
		{TransformTypePRF, PRF_HMAC_SHA2_256, 0},
		{TransformTypePRF, PRF_HMAC_SHA2_384, 0},
		{TransformTypePRF, PRF_HMAC_SHA1, 0},
		{TransformTypePRF, PRF_AES128_XCBC, 0},
		{TransformTypeDH, MODP_2048_bit, 0},
	}
	assertTransforms(t, proposals[0].Transforms, want)
}

type wantTransform struct {
	typ    TransformType
	id     AlgorithmType
	keyLen uint16
}

func assertTransforms(t *testing.T, got []*Transform, want []wantTransform) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("transform count = %d, want %d", len(got), len(want))
	}
	for i, xf := range got {
		if xf.Type != want[i].typ || xf.ID != want[i].id {
			t.Fatalf("transform[%d] = %d/%d, want %d/%d", i, xf.Type, xf.ID, want[i].typ, want[i].id)
		}
		var keyLen uint16
		if len(xf.Attributes) > 0 {
			keyLen = xf.Attributes[0].Val
		}
		if keyLen != want[i].keyLen {
			t.Fatalf("transform[%d] keyLen = %d, want %d", i, keyLen, want[i].keyLen)
		}
	}
}
