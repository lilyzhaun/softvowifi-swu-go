package driver

import (
	"net"
	"testing"
)

func TestOwnershipKernelSessionRekeyCleanup(t *testing.T) {
	isolatedKernel(t)
	owner, peer, nested := NewXFRMManager(), NewXFRMManager(), NewXFRMManager()
	for index, manager := range []*XFRMManager{owner, peer, nested} {
		t.Cleanup(manager.Cleanup)
		mustXFRM(t, manager.AddSA(ownershipSA(uint32(32768+index))))
		mustXFRM(t, manager.AddSP(ownershipSP(32768+index)))
	}
	initialSA, initialSP := ownershipSA(32768), ownershipSP(32768)
	netUndos := []func() error{
		func() error { return owner.DelSA(initialSA.SPI, initialSA.Src, initialSA.Dst, initialSA.Proto) },
		func() error { return owner.DelSP(initialSP) },
	}
	mustXFRM(t, owner.DelSA(initialSA.SPI, initialSA.Src, initialSA.Dst, initialSA.Proto))
	rekeySA := ownershipSA(32771)
	rekeySA.Ifid = initialSA.Ifid
	mustXFRM(t, owner.AddSA(rekeySA))
	rekeySP := initialSP
	rekeySP.TmplSPI = int(rekeySA.SPI)
	mustXFRM(t, owner.AddSP(rekeySP))
	for index := len(netUndos) - 1; index >= 0; index-- {
		mustXFRM(t, netUndos[index]())
	}
	states, policies := kernelCounts(t)
	if states != 3 || policies != 2 {
		t.Fatalf("before production flush: SA=%d SP=%d", states, policies)
	}
	owner.FlushByIP(net.ParseIP("192.0.2.1"))
	mustXFRM(t, owner.cleanupErr)
	states, policies = kernelCounts(t)
	if states != 2 || policies != 2 {
		t.Fatalf("after production flush: SA=%d SP=%d", states, policies)
	}
	peer.Cleanup()
	nested.Cleanup()
	mustXFRM(t, peer.cleanupErr)
	mustXFRM(t, nested.cleanupErr)
	t.Log("actual Session-style Del callbacks then FlushByIP: rekey SA removed, peer and nested resources preserved")
}

func TestOwnershipKernelFlushPoliciesWithoutCallbacks(t *testing.T) {
	isolatedKernel(t)
	owner, peer := NewXFRMManager(), NewXFRMManager()
	t.Cleanup(owner.Cleanup)
	t.Cleanup(peer.Cleanup)
	mustXFRM(t, owner.AddSA(ownershipSA(36864)))
	mustXFRM(t, owner.AddSP(ownershipSP(36864)))
	mustXFRM(t, peer.AddSA(ownershipSA(36865)))
	mustXFRM(t, peer.AddSP(ownershipSP(36865)))
	owner.FlushByIP(net.ParseIP("192.0.2.1"))
	mustXFRM(t, owner.cleanupErr)
	states, policies := kernelCounts(t)
	if states != 1 || policies != 1 {
		t.Fatalf("direct flush: SA=%d SP=%d", states, policies)
	}
	peer.Cleanup()
	mustXFRM(t, peer.cleanupErr)
}
