package swu

import "errors"

// ErrAddressFamilyPolicyTransport prevents silently bypassing an explicit
// Connect policy in an unqualified custom transport or live migration path.
var ErrAddressFamilyPolicyTransport = errors.New("explicit address-family policy requires the built-in connect transport")

func (s *Session) validateRemoteAddressPolicy() error {
	if err := s.remoteAddressFamily.ValidateAddress(s.cfg.EpDGAddr); err != nil {
		return err
	}
	if s.remoteAddressFamily != "" && s.cfg.TransportFactory != nil {
		return ErrAddressFamilyPolicyTransport
	}
	return nil
}
