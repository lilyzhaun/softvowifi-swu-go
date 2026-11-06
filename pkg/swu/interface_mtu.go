package swu

import (
	"errors"
	"fmt"
)

func (s *Session) validateInterfaceMTURequirement() error {
	if !s.requireInterfaceMTU {
		return nil
	}
	if !s.cfg.EnableDriver || (s.cfg.DataplaneMode != "" && s.cfg.DataplaneMode != "tun" && s.cfg.DataplaneMode != "xfrmi") {
		return errors.New("explicit interface MTU requires a TUN or XFRM interface driver")
	}
	if s.interfaceMTU <= 0 {
		return errors.New("explicit interface MTU must be positive")
	}
	return nil
}

func (s *Session) dataPlaneMTU() (int, error) {
	mtu := s.interfaceMTU
	if mtu == 0 {
		// Retain the existing inner-interface budget for ESP-in-UDP overhead.
		mtu = 1358
	}
	if mtu > 0 && mtu < 1280 && s.cpConfig != nil && len(s.cpConfig.IPv6Addresses) > 0 {
		if s.requireInterfaceMTU {
			return 0, errors.New("explicit interface MTU is below the allocated IPv6 minimum")
		}
		mtu = 1280
	}
	return mtu, nil
}

// The setter fails before the data loops start. Keep a failed Close owned by
// the existing cleanup stack, rather than discarding the only TUN handle.
func (s *Session) closeTUNAfterMTUFailure(cause error) error {
	tun := s.tun
	if err := tun.Close(); err != nil {
		s.netUndos = append(s.netUndos, func() error {
			if err := tun.Close(); err != nil {
				return err
			}
			s.tun = nil
			return nil
		})
		return errors.Join(cause, ErrCleanup, fmt.Errorf("close TUN after MTU failure: %w", err))
	}
	s.tun = nil
	return cause
}
