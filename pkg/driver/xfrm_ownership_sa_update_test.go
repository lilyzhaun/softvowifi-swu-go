package driver

import (
	"errors"
	"net"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipSourceMigrationRejectedBeforeMutation(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa := ownershipSA(256)
	mustXFRM(t, owner.AddSA(sa))
	sa.Src = net.ParseIP("192.0.2.9")
	err := owner.UpdateSA(sa)
	if err == nil || kernel.updates != 0 {
		t.Fatal("unsupported source migration reported success or mutated kernel")
	}
}

func TestOwnershipSADirPreserved_whenUpdateOmitsDirection(t *testing.T) {
	for _, recorded := range []netlink.SADir{0, netlink.XFRM_SA_DIR_IN} {
		kernel := newTestKernel()
		owner := kernel.manager(t)
		sa := ownershipSA(256)
		sa.SADir = recorded
		mustXFRM(t, owner.AddSA(sa))
		actual := kernel.states[testSAKey(owner.buildXfrmState(sa))]
		actual.SADir = netlink.XFRM_SA_DIR_IN
		sa.SADir = 0
		sa.TimeLimitSoft = 120
		mustXFRM(t, owner.UpdateSA(sa))
		if kernel.states[testSAKey(owner.buildXfrmState(sa))].SADir != netlink.XFRM_SA_DIR_IN {
			t.Fatal("update omitted verified kernel direction")
		}
	}
}

func TestOwnershipSADirRejected_whenExplicitDirectionDiffersFromKernel(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa := ownershipSA(256)
	sa.SADir = netlink.XFRM_SA_DIR_OUT
	mustXFRM(t, owner.AddSA(sa))
	kernel.states[testSAKey(owner.buildXfrmState(sa))].SADir = netlink.XFRM_SA_DIR_IN
	if err := owner.UpdateSA(sa); !errors.Is(err, ErrXFRMUpdateUnsupported) || kernel.updates != 0 {
		t.Fatalf("explicit kernel direction migration: %v updates=%d", err, kernel.updates)
	}
}
