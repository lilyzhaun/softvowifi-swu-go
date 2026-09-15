package driver

import (
	"errors"
	"sort"
	"syscall"
)

var (
	ErrOwnershipUnconfirmed  = errors.New("XFRM ownership unconfirmed")
	ErrOwnershipChanged      = errors.New("XFRM ownership changed")
	ErrXFRMNotOwned          = errors.New("XFRM resource not owned; key migration is unsupported")
	ErrXFRMUpdateUnsupported = errors.New("XFRM SA update cannot change immutable attributes")
)

type OwnershipError struct {
	Operation string
	Cause     error
}

func (err *OwnershipError) Error() string { return "XFRM " + err.Operation + ": " + err.Cause.Error() }
func (err *OwnershipError) Unwrap() error { return err.Cause }

func ownershipFailure(operation string, cause error) error {
	return &OwnershipError{Operation: operation, Cause: cause}
}

func resourceAbsent(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}

func (x *XFRMManager) nextGeneration() uint64 {
	x.generation++
	return x.generation
}

type ownedUndo struct {
	generation uint64
	run        func() error
}

func (x *XFRMManager) ownedUndoFuncs() []func() error {
	entries := make([]ownedUndo, 0, len(x.states)+len(x.policies))
	for key, record := range x.states {
		generation := record.generation
		entries = append(entries, ownedUndo{generation, func() error {
			x.mu.Lock()
			defer x.mu.Unlock()
			return x.deleteOwnedState(key, generation)
		}})
	}
	for key, record := range x.policies {
		generation := record.generation
		entries = append(entries, ownedUndo{generation, func() error {
			x.mu.Lock()
			defer x.mu.Unlock()
			return x.deleteOwnedPolicy(key, generation)
		}})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].generation < entries[right].generation })
	result := append([]func() error(nil), x.undos...)
	for _, entry := range entries {
		result = append(result, entry.run)
	}
	return result
}

func (x *XFRMManager) cleanupOwned(endpoint string) error {
	var failures error
	for key, record := range x.policies {
		if endpoint == "" || record.endpoints[endpoint] {
			failures = errors.Join(failures, x.deleteOwnedPolicy(key, record.generation))
		}
	}
	for key, record := range x.states {
		if endpoint == "" || record.endpoints[endpoint] {
			failures = errors.Join(failures, x.deleteOwnedState(key, record.generation))
		}
	}
	return failures
}
