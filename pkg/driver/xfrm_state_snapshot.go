package driver

import (
	"crypto/sha256"

	"github.com/iniwex5/netlink"
)

type markIdentity struct{ value, mask uint32 }

func identifyMark(mark *netlink.XfrmMark) markIdentity {
	if mark == nil {
		return markIdentity{}
	}
	mask := mark.Mask
	if mask == 0 {
		mask = ^uint32(0)
	}
	return markIdentity{mark.Value, mask}
}

func (mark markIdentity) query() *netlink.XfrmMark {
	if mark == (markIdentity{}) {
		return nil
	}
	return &netlink.XfrmMark{Value: mark.value, Mask: mark.mask}
}

type algorithmSnapshot struct {
	name          string
	key           [32]byte
	truncate, icv int
}

func snapshotAlgorithm(algorithm *netlink.XfrmStateAlgo) algorithmSnapshot {
	if algorithm == nil {
		return algorithmSnapshot{}
	}
	truncation := algorithm.TruncateLen
	return algorithmSnapshot{algorithm.Name, sha256.Sum256(algorithm.Key), truncation, algorithm.ICVLen}
}

type stateSnapshot struct {
	key                         stateKey
	source                      string
	mode                        netlink.Mode
	reqid, ifid                 int
	auth, crypt, aead           algorithmSnapshot
	encapType                   netlink.EncapType
	sourcePort, destinationPort int
	originalAddress             string
	selector                    policyKey
	outputMark                  markIdentity
	timeSoft, timeHard          uint64
}

func snapshotState(state *netlink.XfrmState) stateSnapshot {
	result := stateSnapshot{
		key: stateIdentity(state), source: state.Src.String(), mode: state.Mode,
		reqid: state.Reqid, ifid: state.Ifid, auth: snapshotAlgorithm(state.Auth),
		crypt: snapshotAlgorithm(state.Crypt), aead: snapshotAlgorithm(state.Aead),
		outputMark: identifyMark(state.OutputMark),
		timeSoft:   state.Limits.TimeSoft, timeHard: state.Limits.TimeHard,
	}
	if state.Encap != nil {
		result.encapType = state.Encap.Type
		result.sourcePort = state.Encap.SrcPort
		result.destinationPort = state.Encap.DstPort
		if state.Encap.OriginalAddress != nil && !state.Encap.OriginalAddress.IsUnspecified() {
			result.originalAddress = state.Encap.OriginalAddress.String()
		}
	}
	selector := state.Selector
	if selector == nil {
		selector = &netlink.XfrmPolicy{}
	}
	result.selector = policyIdentity(selector)
	return result
}
