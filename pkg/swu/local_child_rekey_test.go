package swu

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestLocalChildRekeyOffersTheNegotiatedSuite(t *testing.T) {
	for _, suite := range peerChildSuites {
		t.Run(fmt.Sprintf("%d_%d_%d", suite.encr, suite.integ, suite.bits), func(t *testing.T) {
			s, pipe := childRekeySession(t)
			s.childEncrID, s.childIntegID, s.childEncrKeyLenBits, s.childESN = suite.encr, suite.integ, suite.bits, false
			done := make(chan error, 1)
			go func() { done <- s.rekeyChildSA(newRekeyKernel()) }()
			var raw []byte
			select {
			case raw = <-pipe.sent:
			case <-s.ctx.Done():
				t.Fatal("no local rekey request")
			}
			s.cancel()
			<-done
			sa := peerChildOpen(t, raw, s.Keys.SK_ei, s.Keys.SK_ai)[byte(ikev2.SA)]
			found := false
			for off := 0; off < len(sa); {
				length := int(binary.BigEndian.Uint16(sa[off+2 : off+4]))
				p := sa[off : off+length]
				var encr, integ uint16
				bits := 0
				esn := -1
				for cur := 8 + int(p[6]); cur < len(p); {
					n := int(binary.BigEndian.Uint16(p[cur+2 : cur+4]))
					id := binary.BigEndian.Uint16(p[cur+6 : cur+8])
					switch p[cur+4] {
					case byte(ikev2.TransformTypeEncr):
						encr = id
						if n == 12 && bytes.Equal(p[cur+8:cur+10], []byte{0x80, 14}) {
							bits = int(binary.BigEndian.Uint16(p[cur+10 : cur+12]))
						}
					case byte(ikev2.TransformTypeInteg):
						integ = id
					case byte(ikev2.TransformTypeESN):
						esn = int(id)
					}
					cur += n
				}
				found = found || (encr == suite.encr && integ == suite.integ && bits == suite.bits && esn == 0)
				off += length
			}
			if !found {
				t.Fatal("current negotiated complete suite absent from actual rekey wire")
			}
		})
	}
}

func TestLocalChildRekeyInstallsTheSelectedSuite(t *testing.T) {
	for _, initial := range []peerChildSuite{peerChildSuites[0], peerChildSuites[4]} {
		t.Run(fmt.Sprint(initial.integ), func(t *testing.T) {
			s, _ := childRekeySession(t)
			s.childEncrID, s.childIntegID, s.childEncrKeyLenBits = initial.encr, initial.integ, initial.bits
			kernel := newRekeyKernel()
			if err := exerciseChildRekey(t, s, func() error { return s.rekeyChildSA(kernel) }); err != nil {
				t.Fatal(err)
			}
			if len(kernel.adds) != 2 {
				t.Fatal("missing kernel SA pair")
			}
			for _, sa := range kernel.adds {
				if sa.IsAEAD || sa.CryptAlgoName != "cbc(aes)" || len(sa.CryptKey) != 16 || sa.AuthAlgoName != "hmac(sha256)" || sa.AuthTruncLen != 128 || len(sa.AuthKey) != 32 {
					t.Fatal("kernel used old suite rather than selected CBC128/SHA256")
				}
			}
			if s.childEncrID != uint16(ikev2.ENCR_AES_CBC) || s.childIntegID != uint16(ikev2.AUTH_HMAC_SHA2_256_128) || s.childEncrKeyLenBits != 128 || s.childESN {
				t.Fatal("committed metadata did not follow selected suite")
			}
		})
	}
}

func TestLocalChildRekeyDoesNotResetIKETimer(t *testing.T) {
	s, _ := childRekeySession(t)
	oldIKE := s.lastRekeyTime
	if err := exerciseChildRekey(t, s, func() error { return s.rekeyChildSA(newRekeyKernel()) }); err != nil {
		t.Fatal(err)
	}
	if s.lastRekeyTime != oldIKE || len(s.rekeyResetCh) != 0 || len(s.childRekeyResetCh) != 1 {
		t.Fatal("Child rekey changed IKE cooldown/reset instead of its own")
	}
}
