package swu

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"testing"
)

type changingIdentitySIM struct {
	*vectorSIM
	imsi string
	err  error
}

func (provider *changingIdentitySIM) GetIMSI() (string, error) {
	return provider.imsi, provider.err
}

func Test_AKAIdentity_keysBindLastResponse_whenSIMIdentityChanges(t *testing.T) {
	sess, vector := identitySession(t)
	provider := &changingIdentitySIM{vectorSIM: vector, imsi: "001010000000002"}
	sess.cfg.SIM = provider
	first := identityEAP(t, sess, identityRequest(1, 13, 1, 0, 0))
	provider.imsi = "001010000000001"
	last := identityEAP(t, sess, identityRequest(2, 17, 1, 0, 0))
	if bytes.Equal(first[12:], last[12:]) || !bytes.Equal(last, identityResponse(2, identityNAI)) {
		t.Fatal("fixture did not change last valid identity")
	}
	provider.imsi = "001010000000003"
	keys := referenceAKAKeys(vector, false)
	identityEAP(t, sess, identityChallenge(t, keys[16:32], nil))
	if !bytes.Equal(sess.MSK, keys[32:96]) {
		t.Fatal("MK used current SIM identity instead of last response")
	}
}

func Test_AKAIdentity_doesNotCommitState_whenSIMIdentityUnavailable(t *testing.T) {
	for _, failure := range []error{nil, errors.New("synthetic SIM error")} {
		sess, vector := identitySession(t)
		identityEAP(t, sess, identityRequest(1, 13, 1, 0, 0))
		sess.cfg.SIM = &changingIdentitySIM{vectorSIM: vector, err: failure}
		response, err := sess.handleEAP(identityRequest(2, 17, 1, 0, 0, 250, 1, 0, 0))
		if err == nil || len(response) != 0 || len(sess.akaIdentity.exchanges) != 1 || sess.akaIdentity.extended ||
			string(sess.akaIdentity.selected) != identityNAI || sess.akaIdentity.lastRequest != 13 {
			t.Fatal("invalid identity response committed state")
		}
	}
}

func Test_AKAIdentity_checkcodeCoversAllRounds(t *testing.T) {
	sess, vector := identitySession(t)
	var transcript []byte
	for index, attr := range []byte{13, 17, 10} {
		request := identityRequest(byte(index), attr, 1, 0, 0)
		response := identityEAP(t, sess, request)
		transcript = append(transcript, request...)
		transcript = append(transcript, response...)
	}
	digest := sha1.Sum(transcript)
	keys := referenceAKAKeys(vector, false)
	identityEAP(t, sess, identityChallenge(t, keys[16:32], append([]byte{134, 6, 0, 0}, digest[:]...)))
	if !bytes.Equal(sess.MSK, keys[32:96]) {
		t.Fatal("three-round checkcode failed")
	}
}

func Test_AKAIdentity_independentExpansionMatchesOfficialAOSP(t *testing.T) {
	_, vector := identitySession(t)
	input := append([]byte("0123456789012345"), vector.ik...)
	input = append(input, vector.ck...)
	mk := sha1.Sum(input)
	keys := referenceExpansion(mk[:])
	if !bytes.Equal(keys[16:32], referenceHex(t, "c9500ec59dc62c7d7f5e9e445fa1a3c4")) ||
		!bytes.Equal(keys[32:96], referenceHex(t, "40b9767f5d333645d3b72e9e57effa9dc9d1e7eb598d907948dadb5ad968d52048f0c56a0d68e37e9482f77bc8f689905eab7114eca9fc4ab99d0920d76cf1cf")) {
		t.Fatal("independent reference does not reproduce official identity vector keys")
	}
}
