package ipsec

import (
	"errors"
	"net"
)

// AddressFamilyPolicy applies to remote candidates, never to the DNS endpoint.
// The zero value retains the existing IPv4-first behavior.
type AddressFamilyPolicy string

const (
	AddressFamilyPreferIPv4 AddressFamilyPolicy = "prefer-ipv4"
	AddressFamilyPreferIPv6 AddressFamilyPolicy = "prefer-ipv6"
	AddressFamilyIPv4Only   AddressFamilyPolicy = "ipv4-only"
	AddressFamilyIPv6Only   AddressFamilyPolicy = "ipv6-only"
)

var (
	ErrInvalidAddressFamilyPolicy = errors.New("invalid remote address family policy")
	ErrAddressFamilyMismatch      = errors.New("remote address family does not match policy")
)

// ValidateAddress rejects unknown policy values and conflicting literal hosts.
// Hostnames are checked again against their actual DNS answers before dialing.
func (p AddressFamilyPolicy) ValidateAddress(host string) error {
	switch p {
	case "", AddressFamilyPreferIPv4, AddressFamilyPreferIPv6, AddressFamilyIPv4Only, AddressFamilyIPv6Only:
	default:
		return ErrInvalidAddressFamilyPolicy
	}
	if ip := net.ParseIP(host); ip != nil && !p.permits(ip) {
		return ErrAddressFamilyMismatch
	}
	return nil
}

func (p AddressFamilyPolicy) permits(ip net.IP) bool {
	switch p {
	case AddressFamilyIPv4Only:
		return ip.To4() != nil
	case AddressFamilyIPv6Only:
		return ip.To4() == nil
	default:
		return true
	}
}
