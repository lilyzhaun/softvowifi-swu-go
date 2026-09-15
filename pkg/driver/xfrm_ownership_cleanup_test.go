package driver

import (
	"errors"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipCleanupOwned_whenPolicyIsQuarantined(t *testing.T) {
	kernel := newTestKernel()
	owner, peer := kernel.manager(t), kernel.manager(t)
	mustXFRM(t, owner.AddSA(ownershipSA(256)))
	mustXFRM(t, owner.AddSP(ownershipSP(256)))
	mustXFRM(t, peer.AddSA(ownershipSA(258)))
	mustXFRM(t, peer.AddSP(ownershipSP(258)))
	kernel.getErr = syscall.ENOENT
	if err := owner.AddSP(ownershipSP(257)); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("confirmation: %v", err)
	}
	kernel.getErr = nil
	interfaceUndos := 0
	owner.undos = append(owner.undos, func() error { interfaceUndos++; return nil })
	err := owner.CleanupOwned()
	if !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("quarantine error: %v", err)
	}
	if len(owner.states) != 0 || len(owner.policies) != 1 || len(kernel.states) != 1 || len(kernel.policies) != 2 {
		t.Fatal("confirmed cleanup or peer isolation failed")
	}
	if interfaceUndos != 0 || len(owner.undos) != 1 {
		t.Fatal("SA/SP-only cleanup consumed interface undo")
	}
}

func TestOwnershipCleanupOwnedRetries_whenConfirmedOperationsFail(t *testing.T) {
	for _, operation := range []string{"get", "delete"} {
		t.Run(operation, func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			mustXFRM(t, owner.AddSA(ownershipSA(256)))
			mustXFRM(t, owner.AddSP(ownershipSP(256)))
			switch operation {
			case "get":
				owner.ops.stateGet = func(*netlink.XfrmState) (*netlink.XfrmState, error) { return nil, syscall.EIO }
				owner.ops.policyGet = func(*netlink.XfrmPolicy) (*netlink.XfrmPolicy, error) { return nil, syscall.EAGAIN }
			case "delete":
				owner.ops.stateDel = func(*netlink.XfrmState) error { return syscall.EIO }
				owner.ops.policyDel = func(*netlink.XfrmPolicy) error { return syscall.EAGAIN }
			default:
				t.Fatal("unknown operation")
			}
			err := owner.CleanupOwned()
			var ownershipErr *OwnershipError
			if !errors.Is(err, syscall.EIO) || !errors.Is(err, syscall.EAGAIN) || !errors.As(err, &ownershipErr) || len(owner.UndoFuncs()) != 2 {
				t.Fatalf("aggregated errors or retained records lost: %v", err)
			}
			owner.ops = kernel.manager(t).ops
			mustXFRM(t, owner.CleanupOwned())
			mustXFRM(t, owner.CleanupOwned())
			if len(kernel.states)+len(kernel.policies)+len(owner.UndoFuncs()) != 0 {
				t.Fatal("confirmed cleanup retry did not recover")
			}
		})
	}
}
