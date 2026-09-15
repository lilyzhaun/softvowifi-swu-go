package driver

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

func ownershipSA(spi uint32) XFRMSAConfig {
	return XFRMSAConfig{Src: net.ParseIP("192.0.2.1"), Dst: net.ParseIP("192.0.2.2"),
		SPI: spi, Proto: netlink.XFRM_PROTO_ESP, Ifid: int(spi), Mode: netlink.XFRM_MODE_TUNNEL,
		CryptAlgoName: "cbc(aes)", CryptKey: make([]byte, 16),
		AuthAlgoName: "hmac(sha256)", AuthKey: make([]byte, 32), AuthTruncLen: 128}
}

func ownershipSP(ifid int) XFRMSPConfig {
	return XFRMSPConfig{Src: &net.IPNet{IP: net.ParseIP("198.51.100.1"), Mask: net.CIDRMask(32, 32)},
		Dst: &net.IPNet{IP: net.ParseIP("203.0.113.1"), Mask: net.CIDRMask(32, 32)},
		Dir: netlink.XFRM_DIR_OUT, Ifid: ifid, TmplSrc: net.ParseIP("192.0.2.1"),
		TmplDst: net.ParseIP("192.0.2.2"), TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL}
}

func mustXFRM(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestOwnershipFlushPreservesOtherManagers(t *testing.T) {
	kernel := newTestKernel()
	owner, peer, nested := kernel.manager(t), kernel.manager(t), kernel.manager(t)
	for index, manager := range []*XFRMManager{owner, peer, nested} {
		mustXFRM(t, manager.AddSA(ownershipSA(uint32(256+index))))
		mustXFRM(t, manager.AddSP(ownershipSP(256+index)))
	}
	owner.FlushByIP(net.ParseIP("192.0.2.1"))
	if len(kernel.states) != 2 || len(kernel.policies) != 2 {
		t.Fatalf("remaining states=%d policies=%d", len(kernel.states), len(kernel.policies))
	}
}

func TestOwnershipForeignPolicyCollision(t *testing.T) {
	kernel := newTestKernel()
	owner, stranger := kernel.manager(t), kernel.manager(t)
	mustXFRM(t, owner.AddSP(ownershipSP(0)))
	err := stranger.AddSP(ownershipSP(0))
	if !errors.Is(err, syscall.EEXIST) || kernel.updates != 0 {
		t.Fatalf("exclusive collision: error=%v updates=%d", err, kernel.updates)
	}
}

func TestOwnershipUnknownDelete(t *testing.T) {
	kernel := newTestKernel()
	owner, stranger := kernel.manager(t), kernel.manager(t)
	sa := ownershipSA(256)
	mustXFRM(t, owner.AddSA(sa))
	mustXFRM(t, owner.AddSP(ownershipSP(256)))
	mustXFRM(t, stranger.DelSA(sa.SPI, sa.Src, sa.Dst, sa.Proto))
	mustXFRM(t, stranger.DelSP(ownershipSP(256)))
	stranger.FlushByIP(sa.Src)
	if kernel.deletes != 0 || len(kernel.states) != 1 || len(kernel.policies) != 1 {
		t.Fatal("unknown manager emitted DELETE")
	}
}
