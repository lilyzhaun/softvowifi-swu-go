package driver

import (
	"errors"
	"net"
	"testing"

	"github.com/iniwex5/netlink"
)

// productionWildcardSP mirrors the actual Session/IMS outer-policy shape: an
// all-zero family selector sharing one direction, if_id and IPv4 template
// endpoints.
func productionWildcardSP(selector *net.IPNet, dir netlink.Dir, ifid, spi int) XFRMSPConfig {
	return XFRMSPConfig{
		Src: selector, Dst: selector, Dir: dir, Priority: OuterBroadPolicyPriority,
		TmplSrc: net.ParseIP("192.0.2.1"), TmplDst: net.ParseIP("192.0.2.2"),
		TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
		TmplSPI: spi, Ifid: ifid,
	}
}

func TestOwnershipKernelWildcardFamilyOwnership(t *testing.T) {
	isolatedKernel(t)
	owner := NewXFRMManager()
	t.Cleanup(owner.Cleanup)
	allIPv4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	allIPv6 := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	owner4 := productionWildcardSP(allIPv4, netlink.XFRM_DIR_OUT, 7, 0x100)
	owner6 := productionWildcardSP(allIPv6, netlink.XFRM_DIR_OUT, 7, 0x100)
	peer4 := productionWildcardSP(allIPv4, netlink.XFRM_DIR_OUT, 8, 0x200)
	peer6 := productionWildcardSP(allIPv6, netlink.XFRM_DIR_OUT, 8, 0x200)

	// Foreign controls are installed raw: an unrelated if_id must survive and
	// must not depend on the ownership path under test.
	foreign := []XFRMSPConfig{peer4, peer6}
	for _, cfg := range foreign {
		policy := owner.buildXfrmPolicy(cfg)
		mustXFRM(t, netlink.XfrmPolicyAdd(policy))
		t.Cleanup(func() { _ = netlink.XfrmPolicyDel(policy) })
	}

	// Owner IPv4 wildcard confirms: the dependency resolves an all-zero IPv4
	// selector to the same 0.0.0.0/0 the request used.
	owner4Err := owner.AddSP(owner4)

	// When: the production IPv6 wildcard policy is added after the IPv4 one.
	addErr := owner.AddSP(owner6)

	// Then (private readback): the kernel stores ::/0, but GETPOLICY reports
	// 0.0.0.0/0 because the dependency decoder passes FAMILY_ALL.
	get, getErr := netlink.XfrmPolicyGet(owner.buildXfrmPolicy(owner6))
	listed, listErr := netlink.XfrmPolicyList(netlink.FAMILY_V6)
	reported := "<nil>"
	if get != nil {
		reported = networkIdentity(get.Src) + " -> " + networkIdentity(get.Dst)
	}
	scoped := "<none>"
	for _, policy := range listed {
		if policy.Ifid == owner6.Ifid && policy.Dir == owner6.Dir {
			scoped = networkIdentity(policy.Src) + " -> " + networkIdentity(policy.Dst)
		}
	}
	t.Logf("owner4Err=%v owner6Err=%v unconfirmed=%t changed=%t getErr=%v getSelector=%s familyScopedList=%d scopedSelector=%s listErr=%v",
		owner4Err, addErr, errors.Is(addErr, ErrOwnershipUnconfirmed), errors.Is(addErr, ErrOwnershipChanged),
		getErr, reported, len(listed), scoped, listErr)
	if owner4Err != nil {
		t.Fatalf("owner IPv4 wildcard SP confirmation failed: %v", owner4Err)
	}
	if addErr != nil {
		if !errors.Is(addErr, ErrOwnershipUnconfirmed) {
			t.Fatalf("owner IPv6 wildcard failed for an unexpected reason: %v", addErr)
		}
		t.Fatalf("production IPv6 wildcard SP confirmation failed (selector decoded as %s while kernel/family list reports %s): %v",
			reported, scoped, addErr)
	}

	// Durable target behavior: once IPv6 is confirmed, CleanupOwned removes
	// both owned families and leaves the foreign if_id/family policies intact.
	if err := owner.CleanupOwned(); err != nil {
		t.Fatalf("CleanupOwned: %v", err)
	}
	for name, cfg := range map[string]XFRMSPConfig{"owner4": owner4, "owner6": owner6} {
		if _, err := netlink.XfrmPolicyGet(owner.buildXfrmPolicy(cfg)); !resourceAbsent(err) {
			t.Fatalf("%s survived own cleanup: %v", name, err)
		}
	}
	for name, cfg := range map[string]XFRMSPConfig{"peer4": peer4, "peer6": peer6} {
		if _, err := netlink.XfrmPolicyGet(owner.buildXfrmPolicy(cfg)); err != nil {
			t.Fatalf("%s foreign policy damaged: %v", name, err)
		}
	}
	for _, cfg := range foreign {
		mustXFRM(t, netlink.XfrmPolicyDel(owner.buildXfrmPolicy(cfg)))
	}
	_, policies := kernelCounts(t)
	if policies != 0 {
		t.Fatalf("final policies=%d", policies)
	}
}
