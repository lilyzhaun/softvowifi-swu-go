package swu

import (
	"errors"

	"github.com/iniwex5/netlink"
)

// Prepare both new SAs and policies without deleting either old SA. A failed
// response or installation restores old policies before removing new SAs.
func (s *Session) stagePeerChild(ops childRekeyXFRMOps, next childSARekey) (func() error, error) {
	if ops == nil {
		return func() error { return nil }, nil
	}
	out, in, policies, err := s.childRekeyXFRMConfigs(next)
	if err != nil {
		return nil, err
	}
	oldOut, oldIn := s.ChildSAOut.SPI, s.ChildSAIn.SPI
	addedOut, addedIn, updated := false, false, 0
	undo := func() error {
		var joined error
		for i := updated - 1; i >= 0; i-- {
			p := policies[i]
			p.TmplSPI = int(oldOut)
			if p.Dir == netlink.XFRM_DIR_IN {
				p.TmplSPI = int(oldIn)
			}
			joined = errors.Join(joined, ops.AddSP(p))
		}
		if addedIn {
			joined = errors.Join(joined, ops.DelSA(in.SPI, in.Src, in.Dst, in.Proto))
		}
		if addedOut {
			joined = errors.Join(joined, ops.DelSA(out.SPI, out.Src, out.Dst, out.Proto))
		}
		if joined != nil {
			return errors.Join(ErrCleanup, joined)
		}
		return nil
	}
	if err := ops.AddSA(out); err != nil {
		return nil, err
	}
	addedOut = true
	if err := ops.AddSA(in); err != nil {
		return nil, errors.Join(err, undo())
	}
	addedIn = true
	for i, p := range policies {
		// Both authenticated, same-owner inbound generations may overlap.
		// SPI0 in the policy does not remove the mandatory ESP/if_id scope.
		if p.Dir == netlink.XFRM_DIR_IN {
			p.TmplSPI = 0
		}
		updated = i + 1
		if err := ops.AddSP(p); err != nil {
			return nil, errors.Join(err, undo())
		}
	}
	return undo, nil
}
