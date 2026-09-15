package driver

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestOwnershipPartialInstallMatrix(t *testing.T) {
	for failure := 0; failure < 6; failure++ {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			kernel := newTestKernel()
			owner, peer := kernel.manager(t), kernel.manager(t)
			if failure < 2 {
				mustXFRM(t, peer.AddSA(ownershipSA(uint32(256+failure))))
			} else {
				mustXFRM(t, peer.AddSP(ownershipSP(256+failure)))
			}
			for index := 0; index <= failure; index++ {
				var err error
				if index < 2 {
					err = owner.AddSA(ownershipSA(uint32(256 + index)))
				} else {
					err = owner.AddSP(ownershipSP(256 + index))
				}
				if index == failure {
					if !errors.Is(err, syscall.EEXIST) {
						t.Fatalf("partial collision: %v", err)
					}
				} else {
					mustXFRM(t, err)
				}
			}
			owner.Cleanup()
			if len(kernel.states)+len(kernel.policies) != 1 {
				t.Fatal("partial rollback touched foreign resource or leaked own resource")
			}
			if len(owner.UndoFuncs()) != 0 {
				t.Fatal("retired ownership retained")
			}
		})
	}
}

func TestOwnershipOldUndoAfterKeyReuse(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa, policy := ownershipSA(256), ownershipSP(256)
	mustXFRM(t, owner.AddSA(sa))
	mustXFRM(t, owner.AddSP(policy))
	old := owner.UndoFuncs()
	owner.Cleanup()
	mustXFRM(t, owner.AddSA(sa))
	mustXFRM(t, owner.AddSP(policy))
	for _, undo := range old {
		mustXFRM(t, undo())
	}
	if len(kernel.states) != 1 || len(kernel.policies) != 1 {
		t.Fatal("old generation deleted replacement")
	}
}

func TestOwnershipMutableInputSnapshot(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa, policy := ownershipSA(256), ownershipSP(256)
	policy.Tmpls = []XFRMPolicyTmpl{{Src: policy.TmplSrc, Dst: policy.TmplDst, Proto: policy.TmplProto, Mode: policy.TmplMode}}
	mustXFRM(t, owner.AddSA(sa))
	mustXFRM(t, owner.AddSP(policy))
	sa.Src[len(sa.Src)-1] = 99
	sa.Dst[len(sa.Dst)-1] = 99
	sa.CryptKey[0] = 99
	policy.Src.IP[len(policy.Src.IP)-1] = 99
	policy.Src.Mask[0] = 0
	policy.TmplDst[len(policy.TmplDst)-1] = 99
	policy.Tmpls[0].SPI = 999
	owner.FlushByIP(net.ParseIP("192.0.2.1"))
	mustXFRM(t, owner.cleanupErr)
	if len(kernel.states)+len(kernel.policies) != 0 {
		t.Fatal("caller mutation altered ownership snapshot")
	}
}

func TestOwnershipDeleteFailureRetries(t *testing.T) {
	for _, flush := range []bool{false, true} {
		t.Run(fmt.Sprint(flush), func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			mustXFRM(t, owner.AddSA(ownershipSA(256)))
			mustXFRM(t, owner.AddSP(ownershipSP(256)))
			cleanup := owner.Cleanup
			if flush {
				cleanup = func() { owner.FlushByIP(net.ParseIP("192.0.2.1")) }
			}
			kernel.deleteErr = syscall.EPERM
			cleanup()
			if !errors.Is(owner.cleanupErr, syscall.EPERM) || len(owner.UndoFuncs()) != 2 {
				t.Fatal("delete failure lost retry records")
			}
			kernel.deleteErr = nil
			cleanup()
			mustXFRM(t, owner.cleanupErr)
			cleanup()
			if len(kernel.states)+len(kernel.policies) != 0 || kernel.deletes != 4 {
				t.Fatal("retry or idempotence failed")
			}
		})
	}
}

func TestOwnershipReadFailureDoesNotDelete(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	mustXFRM(t, owner.AddSA(ownershipSA(256)))
	mustXFRM(t, owner.AddSP(ownershipSP(256)))
	kernel.getErr = syscall.EIO
	owner.Cleanup()
	if !errors.Is(owner.cleanupErr, syscall.EIO) || kernel.deletes != 0 || len(owner.UndoFuncs()) != 2 {
		t.Fatal("read failure misreported or destroyed retry state")
	}
	kernel.getErr = nil
	owner.Cleanup()
	mustXFRM(t, owner.cleanupErr)
}

func TestOwnershipPolicyConfirmationFailureRetainsSuccessfulAdd(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	kernel.getErr = syscall.EIO
	err := owner.AddSP(ownershipSP(256))
	if !errors.Is(err, syscall.EIO) || len(kernel.policies) != 1 {
		t.Fatal("confirmation failure not surfaced")
	}
	kernel.getErr = nil
	owner.Cleanup()
	if !errors.Is(owner.cleanupErr, syscall.EIO) || len(kernel.policies) != 1 || len(owner.UndoFuncs()) != 1 {
		t.Fatal("unconfirmed Add must remain quarantined with its original error")
	}
}

func TestOwnershipExternalRemovalRetiresRecords(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	mustXFRM(t, owner.AddSA(ownershipSA(256)))
	mustXFRM(t, owner.AddSP(ownershipSP(256)))
	clear(kernel.states)
	clear(kernel.policies)
	owner.Cleanup()
	mustXFRM(t, owner.cleanupErr)
	if len(owner.UndoFuncs()) != 0 || kernel.deletes != 0 {
		t.Fatal("absent kernel resource was not retired safely")
	}
}
