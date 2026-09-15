package driver

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipAuthTruncation_whenKernelResolvesOmittedRequest(t *testing.T) {
	for _, kernelDefault := range []int{96, 128} {
		t.Run(fmt.Sprint(kernelDefault), func(t *testing.T) {
			kernel := newTestKernel()
			kernel.authTruncDefault = kernelDefault
			owner := kernel.manager(t)
			sa := ownershipSA(256)
			sa.AuthTruncLen = 0
			mustXFRM(t, owner.AddSA(sa))
			record := owner.states[stateIdentity(owner.buildXfrmState(sa))]
			if record.snapshot.auth.truncate != kernelDefault {
				t.Fatalf("frozen truncation=%d want observed kernel response %d", record.snapshot.auth.truncate, kernelDefault)
			}
			sa.TimeLimitSoft = 120
			mustXFRM(t, owner.UpdateSA(sa))
			if record.snapshot.auth.truncate != kernelDefault || record.snapshot.timeSoft != 120 {
				t.Fatalf("update lost frozen truncation=%d soft=%d", record.snapshot.auth.truncate, record.snapshot.timeSoft)
			}
			owner.Cleanup()
			mustXFRM(t, owner.cleanupErr)
			if len(kernel.states) != 0 {
				t.Fatal("omitted-truncation owner was not cleaned after freeze")
			}
		})
	}
}

func TestOwnershipAuthTruncation_detectsTruncationOnlyTamper(t *testing.T) {
	for _, kernelDefault := range []int{96, 128} {
		t.Run(fmt.Sprint(kernelDefault), func(t *testing.T) {
			kernel := newTestKernel()
			kernel.authTruncDefault = kernelDefault
			owner := kernel.manager(t)
			sa := ownershipSA(256)
			sa.AuthTruncLen = 0
			mustXFRM(t, owner.AddSA(sa))
			key := testSAKey(owner.buildXfrmState(sa))
			kernel.states[key].Auth.TruncateLen = kernelDefault + 32
			err := owner.DelSA(sa.SPI, sa.Src, sa.Dst, sa.Proto)
			if !errors.Is(err, ErrOwnershipChanged) || kernel.deletes != 0 || len(owner.states) != 1 {
				t.Fatalf("truncation-only tamper not detected: %v deletes=%d", err, kernel.deletes)
			}
			kernel.states[key].Auth.TruncateLen = kernelDefault
			owner.Cleanup()
			mustXFRM(t, owner.cleanupErr)
		})
	}
}

func TestOwnershipAuthTruncation_whenExplicitRequestNotHonored(t *testing.T) {
	honored := newTestKernel()
	honored.authTruncDefault = 128
	owner := honored.manager(t)
	sa := ownershipSA(256)
	sa.AuthTruncLen = 96
	mustXFRM(t, owner.AddSA(sa))
	if record := owner.states[stateIdentity(owner.buildXfrmState(sa))]; record.snapshot.auth.truncate != 96 {
		t.Fatalf("honored explicit request was not frozen exactly: %d", record.snapshot.auth.truncate)
	}
	mismatch := newTestKernel()
	mismatch.authTruncDefault = 128
	mismatchOwner := mismatch.manager(t)
	get := mismatchOwner.ops.stateGet
	mismatchOwner.ops.stateGet = func(query *netlink.XfrmState) (*netlink.XfrmState, error) {
		actual, err := get(query)
		if err == nil && actual.Auth != nil {
			actual.Auth.TruncateLen = mismatch.authTruncDefault
		}
		return actual, err
	}
	err := mismatchOwner.AddSA(sa)
	if !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.Is(err, ErrOwnershipChanged) || len(mismatch.states) != 1 {
		t.Fatalf("explicit-value mismatch was not quarantined: %v", err)
	}
	clear(mismatch.states)
	mismatchOwner.Cleanup()
}

func TestOwnershipSAQuarantine_whenFirstConfirmationFails(t *testing.T) {
	for _, failure := range []error{syscall.EIO, syscall.ENOENT} {
		for _, action := range []string{"delete", "undo", "cleanup", "flush", "update", "absent"} {
			t.Run(failure.Error()+"/"+action, func(t *testing.T) {
				kernel := newTestKernel()
				owner := kernel.manager(t)
				sa := ownershipSA(256)
				kernel.getErr = failure
				if err := owner.AddSA(sa); !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.Is(err, failure) {
					t.Fatalf("first confirmation: %v", err)
				}
				if len(owner.states) != 1 || kernel.deletes != 0 {
					t.Fatal("failed confirmation did not quarantine")
				}
				kernel.getErr = nil
				get, add, update := owner.ops.stateGet, owner.ops.stateAdd, owner.ops.stateUpdate
				calls := 0
				owner.ops.stateGet = func(query *netlink.XfrmState) (*netlink.XfrmState, error) { calls++; return get(query) }
				owner.ops.stateAdd = func(state *netlink.XfrmState) error { calls++; return add(state) }
				owner.ops.stateUpdate = func(state *netlink.XfrmState) error { calls++; return update(state) }
				if action == "absent" {
					clear(kernel.states)
				}
				writes := kernel.deletes + kernel.updates
				var err error
				switch action {
				case "delete":
					err = owner.DelSA(sa.SPI, sa.Src, sa.Dst, sa.Proto)
				case "undo":
					err = owner.UndoFuncs()[0]()
				case "cleanup", "absent":
					owner.Cleanup()
					err = owner.cleanupErr
				case "flush":
					owner.FlushByIP(sa.Src)
					err = owner.cleanupErr
				case "update":
					err = owner.UpdateSA(sa)
				default:
					t.Fatal("unknown action")
				}
				if !errors.Is(err, ErrOwnershipUnconfirmed) || calls != 0 || kernel.deletes+kernel.updates != writes {
					t.Fatalf("quarantine bypass: %v calls=%d writes=%d", err, calls, kernel.deletes+kernel.updates)
				}
				if len(owner.states) != 1 {
					t.Fatal("quarantined record retired")
				}
			})
		}
	}
}

func TestOwnershipSAQuarantine_whenUpdateConfirmationFails(t *testing.T) {
	for _, failure := range []error{syscall.EIO, syscall.ENOENT} {
		t.Run(failure.Error(), func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			sa := ownershipSA(256)
			mustXFRM(t, owner.AddSA(sa))
			get := owner.ops.stateGet
			gets := 0
			owner.ops.stateGet = func(query *netlink.XfrmState) (*netlink.XfrmState, error) {
				gets++
				if gets == 2 {
					return nil, failure
				}
				return get(query)
			}
			sa.TimeLimitSoft = 120
			if err := owner.UpdateSA(sa); !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.Is(err, failure) || gets != 2 {
				t.Fatalf("post-write confirmation: %v gets=%d", err, gets)
			}
			owner.ops.stateGet = get
			owner.Cleanup()
			if len(kernel.states) != 1 {
				t.Fatalf("unconfirmed write retired the object: %v", owner.cleanupErr)
			}
		})
	}
}

func TestOwnershipSAUpdateFailure_retainsConfirmedRecord(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa := ownershipSA(256)
	mustXFRM(t, owner.AddSA(sa))
	update := owner.ops.stateUpdate
	owner.ops.stateUpdate = func(*netlink.XfrmState) error { return syscall.EIO }
	sa.TimeLimitSoft = 120
	if err := owner.UpdateSA(sa); !errors.Is(err, syscall.EIO) || errors.Is(err, ErrOwnershipUnconfirmed) {
		t.Fatalf("failed write reported as confirmation issue: %v", err)
	}
	owner.ops.stateUpdate = update
	owner.Cleanup()
	mustXFRM(t, owner.cleanupErr)
	if len(kernel.states) != 0 {
		t.Fatal("confirmed record was not retained or deletable")
	}
}

func TestOwnershipCompatibleSnapshot(t *testing.T) {
	base := snapshotState(&netlink.XfrmState{
		Dst: net.ParseIP("192.0.2.2"), Spi: 256, Proto: netlink.XFRM_PROTO_ESP,
		Auth: &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: make([]byte, 32), TruncateLen: 128},
	})
	omitted := base
	omitted.auth.truncate = 0
	if !compatibleSnapshot(omitted, base) {
		t.Fatal("omitted request did not accept frozen kernel truncation")
	}
	tampered := base
	tampered.auth.truncate = 160
	if compatibleSnapshot(tampered, base) {
		t.Fatal("explicit mismatch was accepted")
	}
	tampered = base
	tampered.auth.key = [32]byte{}
	if compatibleSnapshot(tampered, base) {
		t.Fatal("key hash mismatch was accepted")
	}
	explicit := base
	if !compatibleSnapshot(explicit, base) || compatibleSnapshot(explicit, omitted) {
		t.Fatal("explicit equal/invalid comparison wrong")
	}
}

func TestOwnershipAuthTruncation_updateSendsFrozenValue_whenRequestOmitsIt(t *testing.T) {
	kernel := newTestKernel()
	kernel.authTruncDefault = 96
	owner := kernel.manager(t)
	sa := ownershipSA(256)
	sa.AuthTruncLen = 0
	mustXFRM(t, owner.AddSA(sa))
	kernel.authTruncDefault = 128
	sa.TimeLimitSoft = 120
	update := owner.ops.stateUpdate
	owner.ops.stateUpdate = func(state *netlink.XfrmState) error {
		if state.Auth.TruncateLen != 96 {
			t.Fatalf("update sent truncation=%d instead of frozen 96", state.Auth.TruncateLen)
		}
		return update(state)
	}
	mustXFRM(t, owner.UpdateSA(sa))
	if record := owner.states[stateIdentity(owner.buildXfrmState(sa))]; record.snapshot.auth.truncate != 96 {
		t.Fatalf("frozen truncation changed to %d", record.snapshot.auth.truncate)
	}
	kernel.authTruncDefault = 96
	owner.Cleanup()
	mustXFRM(t, owner.cleanupErr)
}
