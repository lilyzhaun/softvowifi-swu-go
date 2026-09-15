package ikev2

const (
	ProposalLayoutMultipleComplete = "multiple-complete"
	ProposalLayoutSingleCombined   = "single-combined"
)

func CreateIKEProposals(layout string, spi []byte) []*Proposal {
	switch layout {
	case ProposalLayoutSingleCombined:
		return CreateCombinedProposalIKE(spi)
	default:
		return CreateMultiProposalIKE(spi)
	}
}

func CreateCombinedProposalIKE(spi []byte) []*Proposal {
	prop := NewProposal(1, ProtoIKE, spi)
	prop.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	prop.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	prop.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	prop.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_384_192, 0)
	prop.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA1_96, 0)
	prop.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_256, 0)
	prop.AddTransform(TransformTypePRF, PRF_HMAC_SHA2_384, 0)
	prop.AddTransform(TransformTypePRF, PRF_HMAC_SHA1, 0)
	prop.AddTransform(TransformTypePRF, PRF_AES128_XCBC, 0)
	prop.AddTransform(TransformTypeDH, MODP_2048_bit, 0)
	return []*Proposal{prop}
}
