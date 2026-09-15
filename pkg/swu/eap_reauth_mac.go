package swu

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"

	"github.com/1239t/swu-go/pkg/eap"
)

func eapReauthAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func eapAKAReauthIntegrityKey(kAut []byte) error {
	if len(kAut) != 16 || eapReauthAllZero(kAut) {
		return errors.New("EAP-AKA reauth integrity key unusable")
	}
	return nil
}

func fillEAPAKAReauthResponseMAC(eapBytes, kAut, nonceS []byte) error {
	if len(eapBytes) < 8 {
		return errors.New("EAP-AKA reauth response too short")
	}
	macAttrOffset, ok := findEAPAttrOffset(eapBytes[8:], eap.AT_MAC)
	if !ok {
		return errors.New("EAP-AKA reauth response missing AT_MAC")
	}
	macPos := 8 + macAttrOffset + 4
	if macPos+16 > len(eapBytes) {
		return errors.New("EAP-AKA reauth response AT_MAC truncated")
	}
	mac := hmac.New(sha1.New, kAut)
	mac.Write(eapBytes)
	mac.Write(nonceS)
	copy(eapBytes[macPos:macPos+16], mac.Sum(nil)[:16])
	return nil
}
