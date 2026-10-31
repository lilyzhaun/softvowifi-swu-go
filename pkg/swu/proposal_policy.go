package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// ErrInvalidProposalPolicy means an explicit local policy cannot be offered.
// It never requests a retry with a wider or default policy.
var ErrInvalidProposalPolicy = errors.New("invalid proposal policy")

// ValidateProposalPolicy checks the same complete policy accepted by Connect.
// It does not create a Session, access a SIM or socket, or mutate Config.
func (c *Config) ValidateProposalPolicy() error {
	if _, _, err := compileIKEPolicy(c); err != nil {
		return err
	}
	_, _, err := compileESPPolicy(c)
	return err
}

// These names identify this library's existing complete suites, not a parser
// for another implementation's configuration language or carrier defaults.
var ikePolicySuites = map[string]struct{ number, dh uint8 }{
	"ike-cbc128-sha256-prfsha256-dh14": {1, 14},
	"ike-cbc256-sha384-prfsha384-dh14": {2, 14},
	"ike-cbc128-sha1-prfsha1-dh14":     {3, 14},
	"ike-cbc256-sha256-prfsha256-dh14": {4, 14},
	"ike-cbc128-sha256-prfsha256-dh2":  {1, 2},
	"ike-cbc256-sha384-prfsha384-dh2":  {2, 2},
	"ike-cbc128-sha1-prfsha1-dh2":      {3, 2},
	"ike-cbc256-sha256-prfsha256-dh2":  {4, 2},
}

var espPolicySuites = map[string]uint8{
	"esp-gcm256-noesn":        1,
	"esp-gcm128-noesn":        2,
	"esp-cbc256-sha256-noesn": 3,
	"esp-cbc128-sha256-noesn": 4,
	"esp-cbc128-sha1-noesn":   5,
	"esp-cbc256-sha512-noesn": 6,
}

type sessionProposalPolicy struct {
	ike, child, initialChild []*ikev2.Proposal
	dh                       uint16
	err                      error
	explicit                 bool
}

// Connect prepares this before opening a socket. Builders also use it so their
// first use has the same boundary. Explicit policies retain owned templates on
// COOKIE, redirect and local Child rekey. Nil policies keep the legacy builder
// and fresh-session single-proposal compatibility behavior.
func (s *Session) prepareProposalPolicy() error {
	if s.proposalPolicy != nil && s.proposalPolicy.explicit {
		return s.proposalPolicy.err
	}
	p := &sessionProposalPolicy{explicit: s.cfg.IKEProposals != nil || s.cfg.ESPProposals != nil}
	s.proposalPolicy = p
	p.ike, p.dh, p.err = compileIKEPolicy(s.cfg)
	if p.err != nil {
		return p.err
	}
	p.child, p.initialChild, p.err = compileESPPolicy(s.cfg)
	return p.err
}

func compileIKEPolicy(c *Config) ([]*ikev2.Proposal, uint16, error) {
	if c.IKEProposals == nil {
		dh, err := effectiveIKEDHGroup(c)
		if err != nil {
			return nil, 0, err
		}
		proposals := ikeProposalsForDHGroup(c.IKEProposalLayout, ikev2.AlgorithmType(dh))
		if n := c.InitialIKEProposalNumber; n != 0 {
			for _, p := range proposals {
				if p.ProposalNum == n && len(p.Transforms) == 4 {
					p.ProposalNum = 1
					return []*ikev2.Proposal{p}, dh, nil
				}
			}
			return nil, 0, errors.New("initial IKE proposal is not a complete original offer")
		}
		return proposals, dh, nil
	}
	if len(c.IKEProposals) == 0 || len(c.IKEProposals) > 4 || c.InitialIKEProposalNumber != 0 {
		return nil, 0, ErrInvalidProposalPolicy
	}
	var proposals []*ikev2.Proposal
	var dh uint16
	seen := make(map[string]bool, len(c.IKEProposals))
	for _, name := range c.IKEProposals {
		suite, ok := ikePolicySuites[name]
		if !ok || seen[name] || dh != 0 && dh != uint16(suite.dh) {
			return nil, 0, ErrInvalidProposalPolicy
		}
		seen[name], dh = true, uint16(suite.dh)
		all := ikeProposalsForDHGroup(ikev2.ProposalLayoutMultipleComplete, ikev2.AlgorithmType(dh))
		p := all[suite.number-1]
		p.ProposalNum = uint8(len(proposals) + 1)
		proposals = append(proposals, p)
	}
	if c.IKEDHGroup != 0 && c.IKEDHGroup != dh {
		return nil, 0, ErrInvalidProposalPolicy
	}
	switch c.IKEProposalLayout {
	case "", ikev2.ProposalLayoutMultipleComplete:
		return proposals, dh, nil
	case ikev2.ProposalLayoutSingleCombined:
		combined, err := combineExactIKEPolicy(proposals)
		return combined, dh, err
	default:
		return nil, 0, ErrInvalidProposalPolicy
	}
}

func combineExactIKEPolicy(proposals []*ikev2.Proposal) ([]*ikev2.Proposal, error) {
	combined := ikev2.NewProposal(1, ikev2.ProtoIKE, nil)
	combinations := 1
	for _, kind := range []ikev2.TransformType{ikev2.TransformTypeEncr, ikev2.TransformTypeInteg, ikev2.TransformTypePRF, ikev2.TransformTypeDH} {
		var alternatives []*ikev2.Transform
		for _, p := range proposals {
			for _, tr := range p.Transforms {
				if tr.Type != kind {
					continue
				}
				found := false
				for _, existing := range alternatives {
					found = found || sameRekeyTransform(tr, existing)
				}
				if !found {
					alternatives = append(alternatives, tr)
				}
			}
		}
		combinations *= len(alternatives)
		combined.Transforms = append(combined.Transforms, alternatives...)
	}
	// RFC 7296 section 3.3: alternatives within one proposal form a product.
	// Unique complete input suites must cover that product, not merely its union.
	if combinations != len(proposals) {
		return nil, ErrInvalidProposalPolicy
	}
	return []*ikev2.Proposal{combined}, nil
}

func compileESPPolicy(c *Config) ([]*ikev2.Proposal, []*ikev2.Proposal, error) {
	all := ikev2.CreateMultiProposalESP(nil)
	if c.ESPProposals != nil {
		if len(c.ESPProposals) == 0 || len(c.ESPProposals) > len(all) || c.InitialChildProposalNumber != 0 || c.EnableESN {
			return nil, nil, ErrInvalidProposalPolicy
		}
		selected := make([]*ikev2.Proposal, 0, len(c.ESPProposals))
		seen := make(map[string]bool, len(c.ESPProposals))
		for _, name := range c.ESPProposals {
			n, ok := espPolicySuites[name]
			if !ok || seen[name] {
				return nil, nil, ErrInvalidProposalPolicy
			}
			seen[name] = true
			p := all[n-1]
			p.ProposalNum = uint8(len(selected) + 1)
			selected = append(selected, p)
		}
		return selected, selected, nil
	}
	initial := all
	if n := c.InitialChildProposalNumber; n != 0 {
		if int(n) > len(all) {
			return nil, nil, errors.New("initial Child proposal is not a complete original offer")
		}
		chosen := *all[n-1]
		chosen.ProposalNum = 1
		initial = []*ikev2.Proposal{&chosen}
	}
	return all, initial, nil
}

// Only proposal numbers and SPI vary in callers. Transform templates remain
// private and immutable, so neither can mutate the captured policy.
func policyProposalsWithSPI(templates []*ikev2.Proposal, spi []byte) []*ikev2.Proposal {
	proposals := make([]*ikev2.Proposal, len(templates))
	for n, p := range templates {
		copy := *p
		copy.SPI = append([]byte(nil), spi...)
		proposals[n] = &copy
	}
	return proposals
}
