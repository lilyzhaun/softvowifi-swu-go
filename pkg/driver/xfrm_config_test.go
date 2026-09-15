package driver

import (
	"net"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestBuildXfrmPolicyMultiTemplatePrioritySelector(t *testing.T) {
	m := NewXFRMManager()
	src := &net.IPNet{IP: net.ParseIP("10.0.0.2").To4(), Mask: net.CIDRMask(32, 32)}
	dst := &net.IPNet{IP: net.ParseIP("10.0.0.1").To4(), Mask: net.CIDRMask(32, 32)}
	cfg := XFRMSPConfig{
		Src:      src,
		Dst:      dst,
		Dir:      netlink.XFRM_DIR_OUT,
		Proto:    6, // TCP
		SrcPort:  5064,
		DstPort:  5062,
		Priority: NestedPolicyPriority,
		Ifid:     42,
		Tmpls: []XFRMPolicyTmpl{
			{
				Src: net.ParseIP("10.0.0.2"), Dst: net.ParseIP("10.0.0.1"),
				Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT,
				SPI: 20, Reqid: 1001,
			},
			{
				Src: net.ParseIP("203.0.113.10"), Dst: net.ParseIP("198.51.100.20"),
				Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
				SPI: 0x0a0b0c0d, Reqid: 0,
			},
		},
	}
	p := m.buildXfrmPolicy(cfg)
	if p.Priority != NestedPolicyPriority {
		t.Fatalf("priority=%d", p.Priority)
	}
	if p.Proto != 6 || p.SrcPort != 5064 || p.DstPort != 5062 {
		t.Fatalf("selector proto/ports=%v %d %d", p.Proto, p.SrcPort, p.DstPort)
	}
	if len(p.Tmpls) != 2 {
		t.Fatalf("tmpls=%d", len(p.Tmpls))
	}
	if p.Tmpls[0].Mode != netlink.XFRM_MODE_TRANSPORT || p.Tmpls[1].Mode != netlink.XFRM_MODE_TUNNEL {
		t.Fatalf("order=%+v", p.Tmpls)
	}
	if p.Tmpls[0].Reqid != 1001 || p.Tmpls[0].Spi != 20 {
		t.Fatalf("inner tmpl=%+v", p.Tmpls[0])
	}
}

func TestBuildXfrmPolicy_encodesZeroOuterSPI(t *testing.T) {
	// Given: nested policy config with outer template SPI 0
	m := NewXFRMManager()
	src := &net.IPNet{IP: net.ParseIP("10.0.0.2").To4(), Mask: net.CIDRMask(32, 32)}
	dst := &net.IPNet{IP: net.ParseIP("10.0.0.1").To4(), Mask: net.CIDRMask(32, 32)}
	cfg := XFRMSPConfig{
		Src: src, Dst: dst, Dir: netlink.XFRM_DIR_OUT,
		Proto: 6, SrcPort: 5064, DstPort: 5062,
		Priority: NestedPolicyPriority, Ifid: 42,
		Tmpls: []XFRMPolicyTmpl{
			{
				Src: net.ParseIP("10.0.0.2"), Dst: net.ParseIP("10.0.0.1"),
				Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT,
				SPI: 20, Reqid: 1001,
			},
			{
				Src: net.ParseIP("203.0.113.10"), Dst: net.ParseIP("198.51.100.20"),
				Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
				SPI: 0, Reqid: 0,
			},
		},
	}

	// When
	p := m.buildXfrmPolicy(cfg)

	// Then: encoded netlink policy keeps SPI 0 and both templates
	if len(p.Tmpls) != 2 {
		t.Fatalf("tmpls=%d want 2", len(p.Tmpls))
	}
	if p.Tmpls[1].Spi != 0 {
		t.Fatalf("outer Spi=%d want 0", p.Tmpls[1].Spi)
	}
	if p.Tmpls[1].Reqid != 0 || p.Tmpls[1].Mode != netlink.XFRM_MODE_TUNNEL {
		t.Fatalf("outer tmpl=%+v", p.Tmpls[1])
	}
	if p.Tmpls[0].Spi != 20 || p.Tmpls[0].Reqid != 1001 {
		t.Fatalf("inner tmpl=%+v", p.Tmpls[0])
	}
	if p.Tmpls[0].Optional != 0 || p.Tmpls[1].Optional != 0 {
		t.Fatalf("Optional=%d/%d want 0 (required transforms)", p.Tmpls[0].Optional, p.Tmpls[1].Optional)
	}
	if p.Tmpls[0].Proto != netlink.XFRM_PROTO_ESP || p.Tmpls[1].Proto != netlink.XFRM_PROTO_ESP {
		t.Fatalf("Proto=%v/%v want ESP", p.Tmpls[0].Proto, p.Tmpls[1].Proto)
	}
}

func TestBuildXfrmStateReqid(t *testing.T) {
	m := NewXFRMManager()
	cfg := XFRMSAConfig{
		Src: net.ParseIP("10.0.0.2"), Dst: net.ParseIP("10.0.0.1"),
		SPI: 99, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT,
		Reqid: 1001, Ifid: 42,
		CryptAlgoName: "ecb(cipher_null)", CryptKey: nil,
		AuthAlgoName: "hmac(sha1)", AuthKey: make([]byte, 20), AuthTruncLen: 96,
	}
	st := m.buildXfrmState(cfg)
	if st.Reqid != 1001 {
		t.Fatalf("reqid=%d", st.Reqid)
	}
	if st.Mode != netlink.XFRM_MODE_TRANSPORT {
		t.Fatalf("mode=%v", st.Mode)
	}
}

func TestOuterBroadPolicyPriorityConstant(t *testing.T) {
	// lower numeric = higher precedence: nested(100) must beat outer(1000)
	if !(NestedPolicyPriority < OuterBroadPolicyPriority) {
		t.Fatalf("nested=%d must be < outer=%d", NestedPolicyPriority, OuterBroadPolicyPriority)
	}
}
