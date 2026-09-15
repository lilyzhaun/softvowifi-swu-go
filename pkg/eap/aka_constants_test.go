package eap

import "testing"

func Test_AKAConstants_matchRFCNumbers_whenCheckcodeAndKDF(t *testing.T) {
	if AT_CHECKCODE != 134 {
		t.Errorf("AT_CHECKCODE = %d, want RFC 4187 section 11 value 134", AT_CHECKCODE)
	}
	if AT_BIDDING != 136 {
		t.Errorf("AT_BIDDING = %d, want RFC 5448 section 4 value 136", AT_BIDDING)
	}
	if AT_KDF_INPUT != 23 || AT_KDF != 24 || AT_NEXT_PSEUDONYM != 132 || AT_NEXT_REAUTH_ID != 133 {
		t.Fatal("KDF or pseudonym numbering differs from RFC 4187/5448")
	}
}
