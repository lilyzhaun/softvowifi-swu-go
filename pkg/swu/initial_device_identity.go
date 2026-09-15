package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/ikev2"
)

var errInitialDeviceIdentity = errors.New("invalid initial device identity: expected 15 nonzero decimal digits")

func (s *Session) buildIKEAuthInitialDevicePayloads() ([]ikev2.Payload, error) {
	if s.cfg.IMEI == "" {
		return s.buildIKEAuthInitPayloads()
	}
	identity, err := initialDeviceIdentity(s.cfg.IMEI)
	if err != nil {
		return nil, err
	}
	payloads, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		return nil, err
	}
	return append(payloads, identity), nil
}

func initialDeviceIdentity(imei string) (*ikev2.EncryptedPayloadNotify, error) {
	if len(imei) != 15 || imei == "000000000000000" {
		return nil, errInitialDeviceIdentity
	}
	data := []byte{0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0xf0}
	for index := range len(imei) {
		digit := imei[index]
		if digit < '0' || digit > '9' {
			return nil, errInitialDeviceIdentity
		}
		data[3+index/2] |= (digit - '0') << (4 * (index % 2))
	}
	return &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.DEVICE_IDENTITY_3GPP,
		NotifyData: data,
	}, nil
}
