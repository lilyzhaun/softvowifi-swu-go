package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

type vectorSIM struct {
	res, ck, ik []byte
	calls       int
}

func (provider *vectorSIM) GetIMSI() (string, error) {
	return "00101" + "0000000001", nil
}

func (provider *vectorSIM) CalculateAKA(rand, autn []byte) ([]byte, []byte, []byte, []byte, error) {
	provider.calls++
	return bytes.Clone(provider.res), bytes.Clone(provider.ck), bytes.Clone(provider.ik), nil, nil
}

func (provider *vectorSIM) Close() error { return nil }

func referenceAKAKeys(provider *vectorSIM, reverse bool) []byte {
	material := []byte("0" + "00101" + "0000000001" + "@nai.epc.mnc001.mcc001.3gppnetwork.org")
	if reverse {
		material = append(material, provider.ck...)
		material = append(material, provider.ik...)
	} else {
		material = append(material, provider.ik...)
		material = append(material, provider.ck...)
	}
	master := sha1.Sum(material)
	return referenceExpansion(master[:])
}

func referenceChallenge(kAut []byte, resultInd bool) []byte {
	raw := []byte{1, 0xa7, 0, 0, 23, 1, 0, 0}
	raw = append(raw, 1, 5, 0, 0)
	raw = append(raw, bytes.Repeat([]byte{0x10}, 16)...)
	raw = append(raw, 2, 5, 0, 0)
	raw = append(raw, bytes.Repeat([]byte{0x20}, 16)...)
	raw = append(raw, 134, 1, 0, 0, 136, 1, 0, 0)
	if resultInd {
		raw = append(raw, 135, 1, 0, 0)
	}
	raw = append(raw, 11, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	mac := hmac.New(sha1.New, kAut)
	mac.Write(raw)
	copy(raw[len(raw)-16:], mac.Sum(nil)[:16])
	return raw
}

func referenceResponse(res, kAut []byte, resultInd bool) []byte {
	words := (4 + len(res) + 3) / 4
	raw := []byte{2, 0xa7, 0, 0, 23, 1, 0, 0, 3, byte(words), 0, byte(len(res) * 8)}
	raw = append(raw, res...)
	raw = append(raw, make([]byte, words*4-4-len(res))...)
	if resultInd {
		raw = append(raw, 135, 1, 0, 0)
	}
	raw = append(raw, 11, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	mac := hmac.New(sha1.New, kAut)
	mac.Write(raw)
	copy(raw[len(raw)-16:], mac.Sum(nil)[:16])
	return raw
}

func Test_EAPAKA_matchesCompleteIndependentResponse_whenRESFourThroughSixteen(t *testing.T) {
	for size := 4; size <= 16; size++ {
		for _, resultInd := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("RES%d/result=%t/reverse=%t", size, resultInd, reverse), func(t *testing.T) {
					provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, size), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
					for index := range provider.res {
						provider.res[index] = byte(0x60 + index)
					}
					keys := referenceAKAKeys(provider, reverse)
					request := referenceChallenge(keys[16:32], resultInd)
					original := bytes.Clone(request)
					want := referenceResponse(provider.res, keys[16:32], resultInd)
					log, output := diagnosticLogger()
					sess := NewSession(&Config{SIM: provider}, log)

					payloads, err := sess.handleEAP(request)

					if err != nil || len(payloads) != 1 {
						t.Fatal("valid synthetic challenge rejected")
					}
					response, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
					if !ok || !bytes.Equal(response.EAPMessage, want) {
						t.Fatal("complete response differs: header, RES bits/padding, result indication or MAC")
					}
					if !bytes.Equal(sess.MSK, keys[32:96]) || !bytes.Equal(sess.eapKAut, keys[16:32]) {
						t.Fatal("committed keys differ from independent expansion")
					}
					if !bytes.Equal(request, original) || provider.calls != 1 {
						t.Fatal("challenge mutated or SIM called more than once")
					}
					assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik)
				})
			}
		}
	}
}

func Test_EAPAKA_rejectsTamperedMAC_whenOtherwiseValid(t *testing.T) {
	provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, 8), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
	keys := referenceAKAKeys(provider, false)
	request := referenceChallenge(keys[16:32], false)
	request[len(request)-1] ^= 1
	original := bytes.Clone(request)
	log, _ := diagnosticLogger()
	sess := NewSession(&Config{SIM: provider}, log)

	payloads, err := sess.handleEAP(request)

	if err == nil || len(payloads) != 0 || sess.MSK != nil || sess.eapKAut != nil || !bytes.Equal(request, original) {
		t.Fatal("bad MAC accepted, committed keys, or mutated request")
	}
}
