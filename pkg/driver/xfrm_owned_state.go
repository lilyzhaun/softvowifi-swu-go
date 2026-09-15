package driver

import (
	"errors"
	"fmt"
	"net"

	"github.com/iniwex5/netlink"
)

type stateKey struct {
	destination string
	spi         int
	proto       netlink.Proto
	mark        markIdentity
}

type ownedState struct {
	generation uint64
	snapshot   stateSnapshot
	confirmErr error
	endpoints  map[string]bool
}

func stateIdentity(state *netlink.XfrmState) stateKey {
	return stateKey{state.Dst.String(), state.Spi, state.Proto, identifyMark(state.Mark)}
}

func (key stateKey) query() *netlink.XfrmState {
	return &netlink.XfrmState{Dst: net.ParseIP(key.destination), Spi: key.spi, Proto: key.proto, Mark: key.mark.query()}
}

func (x *XFRMManager) addOwnedState(state *netlink.XfrmState) error {
	if err := x.ops.stateAdd(state); err != nil {
		return fmt.Errorf("add XFRM SA: %w", err)
	}
	key := stateIdentity(state)
	record := &ownedState{generation: x.nextGeneration(), endpoints: map[string]bool{state.Src.String(): true, state.Dst.String(): true}}
	x.states[key] = record
	actual, err := x.ops.stateGet(key.query())
	if err == nil {
		response := snapshotState(actual)
		if !compatibleSnapshot(snapshotState(state), response) {
			err = ErrOwnershipChanged
		} else {
			record.snapshot = response
		}
	}
	if err != nil {
		record.confirmErr = err
		return ownershipFailure("confirm SA", errors.Join(ErrOwnershipUnconfirmed, err))
	}
	return nil
}

func (x *XFRMManager) checkOwnedState(key stateKey, record *ownedState) (*netlink.XfrmState, error) {
	if record.confirmErr != nil {
		return nil, errors.Join(ErrOwnershipUnconfirmed, record.confirmErr)
	}
	actual, err := x.ops.stateGet(key.query())
	if err != nil {
		return nil, err
	}
	if snapshotState(actual) != record.snapshot {
		return nil, ErrOwnershipChanged
	}
	return actual, nil
}

func (x *XFRMManager) deleteOwnedState(key stateKey, generation uint64) error {
	record := x.states[key]
	if record == nil || (generation != 0 && generation != record.generation) {
		return nil
	}
	_, err := x.checkOwnedState(key, record)
	if err == nil {
		err = x.ops.stateDel(key.query())
	}
	if err != nil && (errors.Is(err, ErrOwnershipUnconfirmed) || !resourceAbsent(err)) {
		return ownershipFailure("delete SA", err)
	}
	delete(x.states, key)
	return nil
}

func (x *XFRMManager) updateOwnedState(cfg XFRMSAConfig) error {
	key := stateIdentity(&netlink.XfrmState{Dst: cfg.Dst, Spi: int(cfg.SPI), Proto: cfg.Proto})
	record := x.states[key]
	if record == nil {
		return ownershipFailure("update SA", ErrXFRMNotOwned)
	}
	actual, err := x.checkOwnedState(key, record)
	if err != nil {
		return ownershipFailure("update SA", err)
	}
	if cfg.SADir != 0 && cfg.SADir != actual.SADir {
		return ownershipFailure("update SA", ErrXFRMUpdateUnsupported)
	}
	effective := cfg
	effective.SADir = actual.SADir
	if effective.AuthTruncLen == 0 {
		effective.AuthTruncLen = record.snapshot.auth.truncate
	}
	state := x.buildXfrmState(effective)
	desired := snapshotState(state)
	immutable := desired
	immutable.sourcePort, immutable.destinationPort = record.snapshot.sourcePort, record.snapshot.destinationPort
	immutable.timeSoft, immutable.timeHard = record.snapshot.timeSoft, record.snapshot.timeHard
	if !compatibleSnapshot(immutable, record.snapshot) {
		return ownershipFailure("update SA", ErrXFRMUpdateUnsupported)
	}
	if err := x.ops.stateUpdate(state); err != nil {
		return fmt.Errorf("update XFRM SA: %w", err)
	}
	response, err := x.ops.stateGet(key.query())
	if err == nil && !compatibleSnapshot(snapshotState(state), snapshotState(response)) {
		err = ErrOwnershipChanged
	}
	if err != nil {
		record.confirmErr = err
		return ownershipFailure("confirm SA", errors.Join(ErrOwnershipUnconfirmed, err))
	}
	record.snapshot = snapshotState(response)
	record.endpoints[state.Src.String()] = true
	record.endpoints[state.Dst.String()] = true
	return nil
}
