package driver

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

func isolatedKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("ISSUE33_KERNEL_TEST") != "1" {
		t.Skip("requires explicit isolated child process")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	mustXFRM(t, err)
	parent := os.Getenv("ISSUE33_PARENT_NETNS")
	if parent == "" || current == parent {
		t.Fatal("refusing kernel operations outside isolated child namespace")
	}
	t.Logf("isolated namespace %s, parent %s", current, parent)
}

func kernelCounts(t *testing.T) (int, int) {
	t.Helper()
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	mustXFRM(t, err)
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	mustXFRM(t, err)
	return len(states), len(policies)
}

func TestOwnershipKernelSharedNamespace(t *testing.T) {
	isolatedKernel(t)
	owner, peer, nested := NewXFRMManager(), NewXFRMManager(), NewXFRMManager()
	for index, manager := range []*XFRMManager{owner, peer, nested} {
		t.Cleanup(manager.Cleanup)
		mustXFRM(t, manager.AddSA(ownershipSA(uint32(4096+index))))
		mustXFRM(t, manager.AddSP(ownershipSP(4096+index)))
	}
	states, policies := kernelCounts(t)
	if states != 3 || policies != 3 {
		t.Fatalf("before: SA=%d SP=%d", states, policies)
	}
	if err := owner.AddSA(ownershipSA(4097)); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("SA collision: %v", err)
	}
	collision := ownershipSA(4097)
	collision.Ifid = 9000
	collision.Src = net.ParseIP("192.0.2.9")
	if err := owner.AddSA(collision); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("same kernel SA key with different source/ifid: %v", err)
	}
	if err := owner.AddSP(ownershipSP(4097)); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("SP collision: %v", err)
	}
	for _, undo := range owner.UndoFuncs() {
		mustXFRM(t, undo())
	}
	owner.FlushByIP(net.ParseIP("192.0.2.1"))
	mustXFRM(t, owner.cleanupErr)
	states, policies = kernelCounts(t)
	if states != 2 || policies != 2 {
		t.Fatalf("after A: SA=%d SP=%d", states, policies)
	}
	for _, spi := range []uint32{4097, 4098} {
		_, err := netlink.XfrmStateGet(peer.buildXfrmState(ownershipSA(spi)))
		mustXFRM(t, err)
	}
	peer.Cleanup()
	nested.Cleanup()
	mustXFRM(t, peer.cleanupErr)
	mustXFRM(t, nested.cleanupErr)
	states, policies = kernelCounts(t)
	if states != 0 || policies != 0 {
		t.Fatalf("final: SA=%d SP=%d", states, policies)
	}
	t.Log("same namespace: 3/3 -> A cleanup 2/2 -> final 0/0; peer and nested SA retained")
}

func TestOwnershipKernelRoundTripAndReplacement(t *testing.T) {
	isolatedKernel(t)
	for _, test := range []struct {
		name      string
		direction netlink.SADir
		replay    int
	}{
		{"out", netlink.XFRM_SA_DIR_OUT, 0},
		{"in", netlink.XFRM_SA_DIR_IN, 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewXFRMManager()
			t.Cleanup(manager.Cleanup)
			sa := ownershipSA(8192)
			sa.SADir = test.direction
			sa.AuthTruncLen = 0
			sa.EncapType = netlink.XFRM_ENCAP_ESPINUDP
			sa.EncapSrcPort, sa.EncapDstPort = 4500, 4500
			mustXFRM(t, manager.AddSA(sa))
			actual, err := netlink.XfrmStateGet(manager.buildXfrmState(sa))
			mustXFRM(t, err)
			if actual.SADir != test.direction || actual.ReplayWindow != test.replay {
				t.Fatalf("installed direction=%d replay=%d, want %d/%d", actual.SADir, actual.ReplayWindow, test.direction, test.replay)
			}
			t.Logf("kernel defaults: auth trunc=%d replay=%d selector=%s/%s", actual.Auth.TruncateLen,
				actual.ReplayWindow, networkIdentity(actual.Selector.Src), networkIdentity(actual.Selector.Dst))
			_, err = manager.checkOwnedState(stateIdentity(actual), manager.states[stateIdentity(actual)])
			mustXFRM(t, err)
			sa.EncapSrcPort = 4600
			sa.SADir = 0
			mustXFRM(t, manager.UpdateSA(sa))
			updated, err := netlink.XfrmStateGet(manager.buildXfrmState(sa))
			mustXFRM(t, err)
			if updated.Encap.SrcPort != 4600 {
				t.Fatal("encapsulation port update did not reach kernel")
			}
			if updated.SADir != actual.SADir || updated.ReplayWindow != test.replay {
				t.Fatalf("update changed direction/replay: %d/%d", updated.SADir, updated.ReplayWindow)
			}
			manager.FlushByIP(net.ParseIP("192.0.2.1"))
			mustXFRM(t, manager.cleanupErr)
			states, _ := kernelCounts(t)
			if states != 0 {
				t.Fatal("original endpoint failed to retire updated SA")
			}
			sa.SADir = test.direction
			mustXFRM(t, manager.AddSA(sa))
			replacement := manager.buildXfrmState(sa)
			replacement.Reqid = 999
			mustXFRM(t, netlink.XfrmStateDel(replacement))
			mustXFRM(t, netlink.XfrmStateAdd(replacement))
			err = manager.DelSA(sa.SPI, sa.Src, sa.Dst, sa.Proto)
			if !errors.Is(err, ErrOwnershipChanged) {
				t.Fatalf("external replacement gate: %v", err)
			}
			mustXFRM(t, netlink.XfrmStateDel(replacement))
			mustXFRM(t, manager.DelSA(sa.SPI, sa.Src, sa.Dst, sa.Proto))
		})
	}
}

func TestOwnershipKernelBaselineSourceUpdate(t *testing.T) {
	isolatedKernel(t)
	manager := NewXFRMManager()
	t.Cleanup(manager.Cleanup)
	sa := ownershipSA(16384)
	mustXFRM(t, manager.AddSA(sa))
	sa.Src = net.ParseIP("192.0.2.3")
	mustXFRM(t, netlink.XfrmStateUpdate(manager.buildXfrmState(sa)))
	actual, err := netlink.XfrmStateGet(manager.buildXfrmState(sa))
	mustXFRM(t, err)
	if !actual.Src.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatal("kernel source-update semantics changed; review unsupported migration contract")
	}
	if err := manager.UpdateSA(sa); !errors.Is(err, ErrXFRMUpdateUnsupported) {
		t.Fatalf("source migration gate: %v", err)
	}
	sa.Dst = net.ParseIP("192.0.2.4")
	err = netlink.XfrmStateUpdate(manager.buildXfrmState(sa))
	if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("baseline destination migration: %v", err)
	}
	manager.Cleanup()
	mustXFRM(t, manager.cleanupErr)
	t.Log("baseline source update ACK preserves old source; destination update ESRCH; owner rejects unsupported migration")
}

func TestOwnershipKernelPolicyRekey(t *testing.T) {
	isolatedKernel(t)
	manager := NewXFRMManager()
	t.Cleanup(manager.Cleanup)
	policy := ownershipSP(12288)
	mustXFRM(t, manager.AddSP(policy))
	policy.TmplSPI = 40000
	mustXFRM(t, manager.AddSP(policy))
	policy.TmplSrc = net.ParseIP("192.0.2.9")
	mustXFRM(t, manager.UpdateSP(policy))
	manager.FlushByIP(net.ParseIP("192.0.2.1"))
	mustXFRM(t, manager.cleanupErr)
	_, policies := kernelCounts(t)
	if policies != 0 {
		t.Fatal("owned rekey/moved policy retained")
	}
}
