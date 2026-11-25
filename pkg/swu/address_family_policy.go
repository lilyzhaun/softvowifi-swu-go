package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/ipsec"
)

// ErrAddressFamilyPolicyTransport prevents silently bypassing an explicit
// Connect policy in an unqualified custom transport or live migration path.
var ErrAddressFamilyPolicyTransport = errors.New("explicit address-family policy requires the built-in connect transport")

// InitialAddressFamilyTimeout is a clean first IKE_SA_INIT exhaustion on an
// explicitly preferred family. An alternate candidate was available; Connect
// itself does not retry it. Only a fresh owner on the same endpoint and network
// should use the returned single-family policy.
type InitialAddressFamilyTimeout struct{ alternate ipsec.AddressFamilyPolicy }

func (*InitialAddressFamilyTimeout) Error() string { return ErrWindowTimeout.Error() }
func (*InitialAddressFamilyTimeout) Unwrap() error { return ErrWindowTimeout }

// FallbackAddressFamily restricts a fresh socket to the previously available alternate.
func (e *InitialAddressFamilyTimeout) FallbackAddressFamily() ipsec.AddressFamilyPolicy {
	return e.alternate
}

func (s *Session) validateRemoteAddressPolicy() error {
	if err := s.remoteAddressFamily.ValidateAddress(s.cfg.EpDGAddr); err != nil {
		return err
	}
	if s.remoteAddressFamily != "" && s.cfg.TransportFactory != nil {
		return ErrAddressFamilyPolicyTransport
	}
	return nil
}
