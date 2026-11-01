package swu

import (
	"bytes"
	"errors"
	"strings"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// ErrInvalidIdentityPolicy never requests a wider or default identity policy.
var ErrInvalidIdentityPolicy = errors.New("invalid IKE identity policy")

// IdentityPolicy selects wire types without replacing identity sources. IDi
// still uses the existing SIM-derived or caller-supplied temporary NAI; the
// requested IDr still uses APN. Peer is an independent exact responder identity
// constraint, not an ePDG DNS name or an implicit copy of the requested IDr.
// Nil preserves legacy types and imposes no additional peer constraint.
type IdentityPolicy struct {
	LocalIDType      uint8
	RequestedIDrType uint8
	Peer             *PeerIdentity
}

// PeerIdentity matches ID Type and Identification Data, excluding RESERVED.
// Data is opaque for KEY_ID, four/sixteen network-order bytes for IP identities,
// or an ASCII FQDN/RFC822 identity. It is never included in policy errors.
type PeerIdentity struct {
	Type uint8
	Data []byte
}

type compiledIdentityPolicy struct {
	explicit                 bool
	localType, requestedType uint8
	peer                     *PeerIdentity
}

// ValidateIdentityPolicy validates the same closed policy captured by
// NewSession without reading the SIM, resolving a name or opening a socket.
func (c *Config) ValidateIdentityPolicy() error {
	_, err := compileIdentityPolicy(c.IdentityPolicy)
	return err
}

func compileIdentityPolicy(p *IdentityPolicy) (*compiledIdentityPolicy, error) {
	if p == nil {
		return &compiledIdentityPolicy{localType: ikev2.ID_RFC822_ADDR, requestedType: ikev2.ID_FQDN}, nil
	}
	if (p.LocalIDType != ikev2.ID_RFC822_ADDR && p.LocalIDType != ikev2.ID_KEY_ID) ||
		(p.RequestedIDrType != ikev2.ID_FQDN && p.RequestedIDrType != ikev2.ID_KEY_ID) {
		return nil, ErrInvalidIdentityPolicy
	}
	out := &compiledIdentityPolicy{explicit: true, localType: p.LocalIDType, requestedType: p.RequestedIDrType}
	if p.Peer != nil {
		if !validIdentityData(p.Peer.Type, p.Peer.Data) {
			return nil, ErrInvalidIdentityPolicy
		}
		out.peer = &PeerIdentity{Type: p.Peer.Type, Data: bytes.Clone(p.Peer.Data)}
	}
	return out, nil
}

func validIdentityData(kind uint8, data []byte) bool {
	if len(data) == 0 || len(data) > 1024 {
		return false
	}
	switch kind {
	case ikev2.ID_KEY_ID:
		return true
	case ikev2.ID_IPV4_ADDR:
		return len(data) == 4
	case ikev2.ID_IPV6_ADDR:
		return len(data) == 16
	case ikev2.ID_FQDN, ikev2.ID_RFC822_ADDR:
		for _, b := range data {
			if b <= 0x20 || b >= 0x7f {
				return false
			}
		}
		name := string(data)
		if kind == ikev2.ID_RFC822_ADDR {
			if strings.Count(name, "@") != 1 {
				return false
			}
			local, domain, _ := strings.Cut(name, "@")
			if local == "" {
				return false
			}
			name = domain
		}
		name = strings.TrimSuffix(name, ".")
		if len(name) == 0 || len(name) > 253 {
			return false
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, b := range []byte(label) {
				if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-') {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

func (s *Session) prepareIdentityPolicy() error {
	// Normal sessions capture in NewSession. The lazy path supports the existing
	// internally constructed sessions used by direct protocol regressions.
	if s.identityPolicy == nil && s.identityPolicyErr == nil {
		s.identityPolicy, s.identityPolicyErr = compileIdentityPolicy(s.cfg.IdentityPolicy)
	}
	return s.identityPolicyErr
}

func (s *Session) checkPeerIdentity(body []byte) error {
	if err := s.prepareIdentityPolicy(); err != nil {
		return err
	}
	peer := s.identityPolicy.peer
	if peer != nil && (body[0] != peer.Type || !bytes.Equal(body[4:], peer.Data)) {
		return authFail("peer_identity")
	}
	return nil
}
