package driver

import (
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipReplayDefaults_whenAddingSA(t *testing.T) {
	for _, test := range []struct {
		name          string
		direction     netlink.SADir
		raw, expected int
	}{
		{"out-zero", netlink.XFRM_SA_DIR_OUT, 0, 0},
		{"in-zero", netlink.XFRM_SA_DIR_IN, 0, 32},
		{"legacy-zero", 0, 0, 32},
		{"out-explicit32", netlink.XFRM_SA_DIR_OUT, 32, 32},
		{"out-explicit-negative", netlink.XFRM_SA_DIR_OUT, -1, -1},
		{"in-explicit64", netlink.XFRM_SA_DIR_IN, 64, 64},
		{"legacy-explicit64", 0, 64, 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			cfg := ownershipSA(256)
			cfg.SADir, cfg.ReplayWindow = test.direction, test.raw
			mustXFRM(t, owner.AddSA(cfg))
			actual := kernel.states[testSAKey(owner.buildXfrmState(cfg))]
			if actual.SADir != test.direction || actual.ReplayWindow != test.expected {
				t.Fatalf("sent direction=%d replay=%d, want %d/%d", actual.SADir, actual.ReplayWindow, test.direction, test.expected)
			}
		})
	}
}

func TestOwnershipReplayDefaults_whenUpdateInheritsKernelDirection(t *testing.T) {
	for _, test := range []struct {
		name          string
		direction     netlink.SADir
		raw, expected int
	}{
		{"out-zero", netlink.XFRM_SA_DIR_OUT, 0, 0},
		{"in-zero", netlink.XFRM_SA_DIR_IN, 0, 32},
		{"legacy-zero", 0, 0, 32},
		{"out-explicit32", netlink.XFRM_SA_DIR_OUT, 32, 32},
		{"in-explicit64", netlink.XFRM_SA_DIR_IN, 64, 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			cfg := ownershipSA(256)
			mustXFRM(t, owner.AddSA(cfg))
			actual := kernel.states[testSAKey(owner.buildXfrmState(cfg))]
			actual.SADir = test.direction
			cfg.ReplayWindow, cfg.TimeLimitSoft = test.raw, 120
			get := owner.ops.stateGet
			gets := 0
			owner.ops.stateGet = func(query *netlink.XfrmState) (*netlink.XfrmState, error) {
				gets++
				if query.SADir != 0 {
					t.Fatal("direction added to ownership GET key")
				}
				return get(query)
			}
			mustXFRM(t, owner.UpdateSA(cfg))
			updated := kernel.states[testSAKey(owner.buildXfrmState(cfg))]
			if gets != 2 || updated.SADir != test.direction || updated.ReplayWindow != test.expected || updated.Limits.TimeSoft != 120 {
				t.Fatalf("update gets=%d direction=%d replay=%d, want 2/%d/%d", gets, updated.SADir, updated.ReplayWindow, test.direction, test.expected)
			}
		})
	}
}
