package swu

import (
	"bytes"
	"fmt"
	"testing"
)

func Test_EAPAKA_diagnosticFixtureLengths_whenSyntheticSuccess(t *testing.T) {
	provider := &diagnosticSIM{}
	res, ck, ik, _, err := provider.CalculateAKA(make([]byte, 16), make([]byte, 16))
	if err != nil || len(res) != 11 || len(ck) != 16 || len(ik) != 16 {
		t.Fatal("existing diagnostic fixture is not a valid AKA success result")
	}
	t.Logf("existing synthetic fixture lengths: RES=%d CK=%d IK=%d", len(res), len(ck), len(ik))
}

func Test_EAPAKA_rejectsInvalidSIMLengths_whenChallengeSucceeds(t *testing.T) {
	for _, method := range []byte{23, 50} {
		for _, lengths := range []struct {
			res, ck, ik int
			message     string
		}{
			{3, 16, 16, "invalid AKA RES length"},
			{17, 16, 16, "invalid AKA RES length"},
			{4, 15, 16, "invalid AKA CK length"},
			{4, 17, 16, "invalid AKA CK length"},
			{4, 16, 15, "invalid AKA IK length"},
			{4, 16, 17, "invalid AKA IK length"},
		} {
			t.Run(fmt.Sprintf("%d/%d/%d/%d", method, lengths.res, lengths.ck, lengths.ik), func(t *testing.T) {
				provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, lengths.res), ck: bytes.Repeat([]byte{0x43}, lengths.ck), ik: bytes.Repeat([]byte{0x49}, lengths.ik)}
				keys := referenceAKAKeys(provider, false)
				request := referenceChallenge(keys[16:32], false)
				request[4] = method
				if method == 50 {
					request = primeStandardRequest(t, primeStandardVectors[0], false, 1)
				}
				original := bytes.Clone(request)
				log, output := diagnosticLogger()
				sess := NewSession(&Config{SIM: provider}, log)
				if method == 50 {
					sess.akaIdentity.outer = []byte(primePublicIdentity)
				}

				payloads, err := sess.handleEAP(request)

				if err == nil || err.Error() != lengths.message {
					t.Fatalf("invalid SIM result: error_present=%t response_count=%d msk_length=%d", err != nil, len(payloads), len(sess.MSK))
				}
				if len(payloads) != 0 || sess.MSK != nil || sess.eapKAut != nil {
					t.Fatal("invalid SIM result produced a response or committed keys")
				}
				if provider.calls != 1 || !bytes.Equal(request, original) {
					t.Fatal("SIM call count or input changed")
				}
				assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik)
			})
		}
	}
}
