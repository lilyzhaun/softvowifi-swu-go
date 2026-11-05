package driver

import (
	"errors"
	"strconv"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestESNReplayDefaultsReachBothActualSARequests(t *testing.T) {
	for _, direction := range []netlink.SADir{netlink.XFRM_SA_DIR_OUT, netlink.XFRM_SA_DIR_IN, 0} {
		t.Run(strconv.Itoa(int(direction)), func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			cfg := ownershipSA(256)
			cfg.ESN, cfg.SADir = true, direction
			mustXFRM(t, owner.AddSA(cfg))
			actual := kernel.states[testSAKey(owner.buildXfrmState(cfg))]
			if !actual.ESN || actual.ReplayWindow != 32 {
				t.Fatal("actual ESN SA request did not retain a supported positive replay window")
			}
		})
	}
}

func TestESNActualReadbackMismatchCannotConfirmOwnership(t *testing.T) {
	for _, variant := range []string{"missing-flag", "unexpected-flag", "changed-window"} {
		t.Run(variant, func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			cfg := ownershipSA(256)
			cfg.ESN, cfg.ReplayWindow = variant != "unexpected-flag", 32
			get := owner.ops.stateGet
			owner.ops.stateGet = func(query *netlink.XfrmState) (*netlink.XfrmState, error) {
				actual, err := get(query)
				if err != nil {
					return nil, err
				}
				switch variant {
				case "missing-flag":
					actual.ESN = false
				case "unexpected-flag":
					actual.ESN = true
				case "changed-window":
					actual.ReplayWindow = 64
				}
				return actual, nil
			}
			if err := owner.AddSA(cfg); !errors.Is(err, ErrOwnershipUnconfirmed) || !errors.Is(err, ErrOwnershipChanged) {
				t.Fatal("actual ESN/window mismatch was accepted as owned")
			}
		})
	}
}

func TestESNFlagDriftPreventsDeletingForeignState(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	cfg := ownershipSA(256)
	cfg.ESN, cfg.ReplayWindow = true, 32
	mustXFRM(t, owner.AddSA(cfg))
	kernel.states[testSAKey(owner.buildXfrmState(cfg))].ESN = false
	if err := owner.DelSA(cfg.SPI, cfg.Src, cfg.Dst, cfg.Proto); !errors.Is(err, ErrOwnershipChanged) {
		t.Fatal("changed ESN owner was not refused before DELETE")
	}
	if kernel.deletes != 0 || len(kernel.states) != 1 {
		t.Fatal("foreign ESN state was deleted")
	}
}

func TestESNWindowDriftPreventsLifetimeUpdate(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	cfg := ownershipSA(256)
	cfg.ESN, cfg.ReplayWindow = true, 32
	mustXFRM(t, owner.AddSA(cfg))
	kernel.states[testSAKey(owner.buildXfrmState(cfg))].ReplayWindow = 64
	cfg.TimeLimitSoft = 120
	if err := owner.UpdateSA(cfg); !errors.Is(err, ErrOwnershipChanged) {
		t.Fatal("changed ESN replay layout was not refused before lifetime update")
	}
	if kernel.updates != 0 {
		t.Fatal("foreign ESN replay layout was overwritten")
	}
}
