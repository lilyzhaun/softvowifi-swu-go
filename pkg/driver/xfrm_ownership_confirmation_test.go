package driver

import (
	"errors"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipQuarantine_whenFirstConfirmationFails(t *testing.T) {
	for _, firstFailure := range []error{syscall.EIO, syscall.ENOENT} {
		for _, action := range []string{"delete", "update", "add", "cleanup", "owned", "flush", "undo", "absent"} {
			t.Run(firstFailure.Error()+"/"+action, func(t *testing.T) {
				kernel := newTestKernel()
				owner := kernel.manager(t)
				cfg := ownershipSP(256)
				kernel.getErr = firstFailure
				if err := owner.AddSP(cfg); !errors.Is(err, firstFailure) {
					t.Fatalf("confirmation error: %v", err)
				}
				key := policyIdentity(owner.buildXfrmPolicy(cfg))
				record := owner.policies[key]
				stored := kernel.policies[testSPKey(owner.buildXfrmPolicy(cfg))]
				stored.Index += 8
				kernel.getErr = nil
				calls := 0
				get, add := owner.ops.policyGet, owner.ops.policyAdd
				owner.ops.policyGet = func(query *netlink.XfrmPolicy) (*netlink.XfrmPolicy, error) {
					calls++
					return get(query)
				}
				owner.ops.policyAdd = func(policy *netlink.XfrmPolicy) error { calls++; return add(policy) }
				if action == "absent" {
					clear(kernel.policies)
				}
				var err error
				switch action {
				case "delete":
					err = owner.DelSP(cfg)
				case "update":
					err = owner.UpdateSP(cfg)
				case "add":
					err = owner.AddSP(cfg)
				case "cleanup", "absent":
					owner.Cleanup()
					err = owner.cleanupErr
				case "owned":
					err = owner.CleanupOwned()
				case "flush":
					owner.FlushByIP(cfg.TmplSrc)
					err = owner.cleanupErr
				case "undo":
					err = owner.UndoFuncs()[0]()
				default:
					t.Fatal("unknown action")
				}
				if !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.Is(err, firstFailure) || calls != 0 || kernel.deletes != 0 || kernel.updates != 0 {
					t.Errorf("quarantine bypass: err=%v reads/adds=%d deletes=%d updates=%d", err, calls, kernel.deletes, kernel.updates)
				}
				if owner.policies[key] != record || record.index != 0 {
					t.Error("quarantined record retired or adopted a late index")
				}
				if action != "absent" && kernel.policies[testSPKey(owner.buildXfrmPolicy(cfg))] != stored {
					t.Error("replacement changed")
				}
			})
		}
	}
}

func TestOwnershipConfirmationRejectsInvalidIdentity(t *testing.T) {
	for _, failure := range []string{"zero-index", "fingerprint"} {
		t.Run(failure, func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			get := owner.ops.policyGet
			owner.ops.policyGet = func(query *netlink.XfrmPolicy) (*netlink.XfrmPolicy, error) {
				actual, err := get(query)
				if err != nil {
					return nil, err
				}
				switch failure {
				case "zero-index":
					actual.Index = 0
				case "fingerprint":
					actual.Priority++
				default:
					t.Fatal("unknown identity failure")
				}
				return actual, nil
			}
			err := owner.AddSP(ownershipSP(256))
			var ownershipErr *OwnershipError
			if !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.As(err, &ownershipErr) {
				t.Fatalf("invalid identity confirmed ownership: %v", err)
			}
			owner.ops.policyGet = func(*netlink.XfrmPolicy) (*netlink.XfrmPolicy, error) {
				t.Fatal("quarantine performed late GET")
				return nil, syscall.EIO
			}
			if err := owner.CleanupOwned(); !errors.Is(err, ErrOwnershipUnconfirmed) || len(owner.policies) != 1 || kernel.deletes != 0 {
				t.Fatalf("invalid identity quarantine lost: %v", err)
			}
		})
	}
}
