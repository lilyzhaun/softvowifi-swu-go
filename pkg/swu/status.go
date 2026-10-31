package swu

import (
	"context"
	"net"
)

// NegotiatedSecurity contains only the current authenticated transform tuples.
// It is not a kernel-state readback or proof of application traffic.
type NegotiatedSecurity struct {
	IKE   NegotiatedIKESecurity
	Child NegotiatedChildSecurity
}

type NegotiatedIKESecurity struct {
	Encryption uint16
	KeyBits    int
	Integrity  uint16
	PRF        uint16
	DH         uint16
}

type NegotiatedChildSecurity struct {
	Encryption uint16
	KeyBits    int
	Integrity  uint16
	ESN        bool
	// PFS is the additional Child DH group. The current authenticated and
	// rekey selectors reject additional DH, so zero means no additional PFS.
	PFS uint16
}

// childMu protects publication and retirement. IKE rekey requires the same
// complete tuple; Child rekey can select another tuple under that same lock.
type sessionSecurity struct {
	owner context.Context
	ike   NegotiatedIKESecurity
}

// Called only by Connect after final AUTH and any enabled dataplane setup.
func (s *Session) publishNegotiatedSecurity() {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	s.security = &sessionSecurity{owner: s.ctx, ike: NegotiatedIKESecurity{
		Encryption: s.ikeEncrID, KeyBits: s.ikeEncrKeyLenBits,
		Integrity: s.ikeIntegID, PRF: s.ikePRFID, DH: s.ikeDHID,
	}}
}

type SessionSnapshot struct {
	Established bool
	TUNName     string

	IPv4       net.IP
	IPv6       net.IP
	IPv6Prefix int

	DNSv4 []net.IP
	DNSv6 []net.IP

	PCSCFv4 []net.IP
	PCSCFv6 []net.IP

	// Security is nil until authentication and dataplane readiness, and as
	// soon as the authenticated owner is canceled or retired.
	Security *NegotiatedSecurity
}

func (s *Session) Snapshot() SessionSnapshot {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	out := SessionSnapshot{}
	out.Established = s.ChildSAIn != nil && s.ChildSAOut != nil
	// 启用了数据平面驱动时
	if s.cfg.EnableDriver {
		switch s.cfg.DataplaneMode {
		case "xfrmi":
			if out.Established && s.xfrmMgr == nil {
				out.Established = false
			}
			if s.xfrmMgr != nil {
				out.TUNName = s.cfg.TUNName
			}
		case "netstack":
			if out.Established && s.innerRx == nil {
				out.Established = false
			}
			out.TUNName = "netstack"
		default:
			if out.Established && s.tun == nil {
				out.Established = false
			}
			if s.tun != nil {
				out.TUNName = s.tun.DeviceName()
			}
		}
	} else {
		// 无驱动模式下，只看 SA
	}
	if out.Established && s.security != nil && s.security.owner.Err() == nil {
		out.Security = &NegotiatedSecurity{
			IKE: s.security.ike,
			Child: NegotiatedChildSecurity{
				Encryption: s.childEncrID, KeyBits: s.childEncrKeyLenBits,
				Integrity: s.childIntegID, ESN: s.childESN,
			},
		}
	}
	if s.cpConfig != nil {
		if len(s.cpConfig.IPv4Addresses) > 0 {
			out.IPv4 = append(net.IP(nil), s.cpConfig.IPv4Addresses[0]...)
		}
		if len(s.cpConfig.IPv6Addresses) > 0 {
			out.IPv6 = append(net.IP(nil), s.cpConfig.IPv6Addresses[0]...)
		}
		if s.cpConfig.IPv6Prefix != 0 {
			out.IPv6Prefix = int(s.cpConfig.IPv6Prefix)
		}
		for _, ip := range s.cpConfig.IPv4DNS {
			out.DNSv4 = append(out.DNSv4, append(net.IP(nil), ip...))
		}
		for _, ip := range s.cpConfig.IPv6DNS {
			out.DNSv6 = append(out.DNSv6, append(net.IP(nil), ip...))
		}
		for _, ip := range s.cpConfig.IPv4PCSCF {
			out.PCSCFv4 = append(out.PCSCFv4, append(net.IP(nil), ip...))
		}
		for _, ip := range s.cpConfig.IPv6PCSCF {
			out.PCSCFv6 = append(out.PCSCFv6, append(net.IP(nil), ip...))
		}
	}
	if out.IPv6Prefix == 0 && out.IPv6 != nil {
		out.IPv6Prefix = 64
	}
	return out
}
