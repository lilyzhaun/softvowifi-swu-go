package driver

import (
	"net"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipKernelAlgorithmDefaults(t *testing.T) {
	isolatedKernel(t)
	for _, algorithm := range []struct {
		name string
		size int
	}{
		{"hmac(md5)", 16},
		{"hmac(sha1)", 20},
		{"hmac(sha256)", 32},
		{"hmac(sha384)", 48},
		{"hmac(sha512)", 64},
	} {
		t.Run(algorithm.name, func(t *testing.T) {
			manager := NewXFRMManager()
			t.Cleanup(manager.Cleanup)
			sa := ownershipSA(20480)
			sa.AuthAlgoName, sa.AuthKey, sa.AuthTruncLen = algorithm.name, make([]byte, algorithm.size), 0
			mustXFRM(t, manager.AddSA(sa))
			actual, err := netlink.XfrmStateGet(manager.buildXfrmState(sa))
			mustXFRM(t, err)
			t.Logf("kernel-resolved truncation=%d frozen by confirmation", actual.Auth.TruncateLen)
			if _, err := manager.checkOwnedState(stateIdentity(actual), manager.states[stateIdentity(actual)]); err != nil {
				t.Fatalf("frozen snapshot does not match observed kernel response: %v", err)
			}
			manager.Cleanup()
			mustXFRM(t, manager.cleanupErr)
			states, _ := kernelCounts(t)
			if states != 0 {
				t.Fatal("default-truncation SA retained after cleanup")
			}
		})
	}
}

func TestOwnershipKernelIPv6AEADSelector(t *testing.T) {
	isolatedKernel(t)
	manager := NewXFRMManager()
	t.Cleanup(manager.Cleanup)
	sa := ownershipSA(24576)
	sa.Src, sa.Dst = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	sa.IsAEAD, sa.AeadAlgoName, sa.AeadKey, sa.AeadICVLen = true, "rfc4106(gcm(aes))", make([]byte, 20), 128
	sa.Mode = netlink.XFRM_MODE_TRANSPORT
	sa.SelSrc = &net.IPNet{IP: sa.Src, Mask: net.CIDRMask(128, 128)}
	sa.SelDst = &net.IPNet{IP: sa.Dst, Mask: net.CIDRMask(128, 128)}
	sa.SelProto, sa.SelSrcPort, sa.SelDstPort = 6, 40000, 40001
	mustXFRM(t, manager.AddSA(sa))
	manager.Cleanup()
	mustXFRM(t, manager.cleanupErr)
	states, _ := kernelCounts(t)
	if states != 0 {
		t.Fatal("IPv6 AEAD selector cleanup failed")
	}
}

func TestOwnershipKernelPolicyIndexReplacement(t *testing.T) {
	isolatedKernel(t)
	manager := NewXFRMManager()
	t.Cleanup(manager.Cleanup)
	policy := ownershipSP(28672)
	mustXFRM(t, manager.AddSP(policy))
	query := manager.buildXfrmPolicy(policy)
	old, err := netlink.XfrmPolicyGet(query)
	mustXFRM(t, err)
	mustXFRM(t, netlink.XfrmPolicyDel(old))
	mustXFRM(t, netlink.XfrmPolicyAdd(query))
	replacement, err := netlink.XfrmPolicyGet(query)
	mustXFRM(t, err)
	if replacement.Index == old.Index {
		t.Fatal("kernel reused policy index; replacement scenario not established")
	}
	manager.Cleanup()
	mustXFRM(t, manager.cleanupErr)
	_, policies := kernelCounts(t)
	if policies != 1 {
		t.Fatal("old index cleanup deleted replacement policy")
	}
	mustXFRM(t, netlink.XfrmPolicyDel(replacement))
}
