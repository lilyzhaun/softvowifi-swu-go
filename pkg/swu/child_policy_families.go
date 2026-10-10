package swu

import (
	"net"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/iniwex5/netlink"
)

// This preserves the existing broad-policy shape within each active family.
// Exact arbitrary TS address/port compilation is a separate capability.
func (s *Session) childPolicyFamilyActive(family uint8) bool {
	if s.cpConfig == nil {
		return false
	}
	if family == ikev2.TS_IPV4_ADDR_RANGE && len(s.cpConfig.IPv4Addresses) == 0 {
		return false
	}
	if family == ikev2.TS_IPV6_ADDR_RANGE && len(s.cpConfig.IPv6Addresses) == 0 {
		return false
	}
	for _, local := range s.tsi {
		if local.TSType != family {
			continue
		}
		for _, remote := range s.tsr {
			if selectorsShareFamilyProtocol(local, remote) {
				return true
			}
		}
	}
	return false
}

func (s *Session) childPolicyNetworks() []*net.IPNet {
	var networks []*net.IPNet
	if s.childPolicyFamilyActive(ikev2.TS_IPV4_ADDR_RANGE) {
		networks = append(networks, &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)})
	}
	if s.childPolicyFamilyActive(ikev2.TS_IPV6_ADDR_RANGE) {
		networks = append(networks, &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)})
	}
	return networks
}

func (s *Session) initialChildXFRMPolicies() []driver.XFRMSPConfig {
	var policies []driver.XFRMSPConfig
	for _, network := range s.childPolicyNetworks() {
		out := driver.XFRMSPConfig{
			Src: network, Dst: network, Dir: netlink.XFRM_DIR_OUT, Priority: driver.OuterBroadPolicyPriority,
			TmplSrc: s.xfrmLocalIP, TmplDst: s.xfrmRemoteIP, TmplProto: netlink.XFRM_PROTO_ESP,
			TmplMode: netlink.XFRM_MODE_TUNNEL, TmplSPI: int(s.ChildSAOut.SPI), Ifid: s.xfrmIfID,
		}
		in := out
		in.Dir = netlink.XFRM_DIR_IN
		in.TmplSrc, in.TmplDst = s.xfrmRemoteIP, s.xfrmLocalIP
		in.TmplSPI = int(s.ChildSAIn.SPI)
		policies = append(policies, out, in)
		if network.IP.To4() != nil {
			forward := in
			forward.Dir = netlink.XFRM_DIR_FWD
			forward.TmplSPI = 0
			policies = append(policies, forward)
		}
	}
	return policies
}
