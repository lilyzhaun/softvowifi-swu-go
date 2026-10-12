package swu

import (
	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func (s *Session) deriveChildRekey(encr, integ uint16, bits int, ni, nr []byte, localSPI, peerSPI uint32, localInitiator bool) (childSARekey, error) {
	var next childSARekey
	enc, err := crypto.GetEncrypterWithKeyLen(encr, bits)
	if err != nil {
		return next, err
	}
	keyLen, authLen := enc.KeySize(), 0
	aead := driver.IsAEADAlgorithm(encr)
	var auth crypto.IntegrityAlgorithm
	if aead {
		keyLen += 4
	} else {
		auth, err = crypto.GetIntegrityAlgorithm(integ)
		if err != nil {
			return next, err
		}
		authLen = auth.KeySize()
	}
	seed := append(append([]byte(nil), ni...), nr...)
	km, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, 2*(keyLen+authLen))
	if err != nil {
		return next, err
	}
	ei, ai := km[:keyLen], km[keyLen:keyLen+authLen]
	er, ar := km[keyLen+authLen:2*keyLen+authLen], km[2*keyLen+authLen:]
	if !localInitiator {
		ei, er = er, ei
		ai, ar = ar, ai
	}
	if aead {
		next.out = ipsec.NewSecurityAssociation(peerSPI, enc, ei, nil)
		next.in = ipsec.NewSecurityAssociation(localSPI, enc, er, nil)
	} else {
		next.out = ipsec.NewSecurityAssociationCBC(peerSPI, enc, ei, auth, ai)
		next.in = ipsec.NewSecurityAssociationCBC(localSPI, enc, er, auth, ar)
	}
	next.out.RemoteSPI, next.in.RemoteSPI = localSPI, peerSPI
	next.encrID, next.keyBits = encr, bits
	return next, nil
}
