package swu

import "errors"

// ErrInvalidInnerAddressFamily rejects unsupported captured CP/TS policies
// before network or SIM use, without echoing caller data.
var ErrInvalidInnerAddressFamily = errors.New("invalid inner address family")

func (s *Session) innerAddressFamilies() (ipv4, ipv6 bool, err error) {
	switch s.innerAddressFamily {
	case "", "dual-stack":
		return true, true, nil
	case "ipv4":
		return true, false, nil
	case "ipv6":
		return false, true, nil
	default:
		return false, false, ErrInvalidInnerAddressFamily
	}
}
