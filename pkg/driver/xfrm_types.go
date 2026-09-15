package driver

import (
	"net"

	"github.com/iniwex5/netlink"
)

// Policy priority: lower numeric value = higher precedence in Linux XFRM.
const (
	NestedPolicyPriority     = 100
	OuterBroadPolicyPriority = 1000
)

// XFRMSAConfig XFRM Security Association 配置
type XFRMSAConfig struct {
	Src   net.IP
	Dst   net.IP
	SPI   uint32
	Proto netlink.Proto

	IsAEAD bool

	AeadAlgoName string
	AeadKey      []byte
	AeadICVLen   int

	CryptAlgoName string
	CryptKey      []byte
	AuthAlgoName  string
	AuthKey       []byte
	AuthTruncLen  int

	EncapType    netlink.EncapType
	EncapSrcPort int
	EncapDstPort int

	Ifid int
	Mode netlink.Mode

	// Reqid associates state with nested policy templates (0 = unset / outer).
	Reqid int

	TimeLimitSoft uint64
	TimeLimitHard uint64
	ReplayWindow  int
	SADir         netlink.SADir
	ESN           bool

	// Optional selector for transport-mode SA matching.
	SelSrc     *net.IPNet
	SelDst     *net.IPNet
	SelProto   netlink.Proto
	SelSrcPort int
	SelDstPort int
}

// XFRMPolicyTmpl is one ordered transform template in a policy.
type XFRMPolicyTmpl struct {
	Src   net.IP
	Dst   net.IP
	Proto netlink.Proto
	Mode  netlink.Mode
	SPI   int
	Reqid int
}

// XFRMSPConfig XFRM Security Policy 配置
type XFRMSPConfig struct {
	Src *net.IPNet
	Dst *net.IPNet
	Dir netlink.Dir

	// Selector fields (0 = any).
	Proto   netlink.Proto
	SrcPort int
	DstPort int

	// Priority: lower number = higher precedence. Outer broad policies use OuterBroadPolicyPriority.
	Priority int

	// Legacy single-template fields (used when Tmpls is empty).
	TmplSrc   net.IP
	TmplDst   net.IP
	TmplProto netlink.Proto
	TmplMode  netlink.Mode
	TmplSPI   int
	TmplReqid int

	// Ordered multi-template list. When non-empty, overrides legacy single-template fields.
	// Nested SIP: [inner transport, outer tunnel]. Outer tunnel SPI is 0 (wildcard);
	// inner transport SPI/reqid stay exact. Inbound verifies reverse order.
	Tmpls []XFRMPolicyTmpl

	Ifid int
}
