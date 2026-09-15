package swu

import "net"

// OuterXFRMContext is a read-only snapshot of the current outer SWu tunnel-mode
// XFRM state needed to nest IMS transport-mode SAs.
//
// OutboundSPI/InboundSPI prove an outer Child SA is ready (non-zero). Nested
// policy outer templates use SPI 0 so they survive Child SA replacement; this
// snapshot is not used as a policy pin. Callers still need a fresh context when
// the tunnel session itself is replaced (new endpoints or if_id).
type OuterXFRMContext struct {
	LocalIP     net.IP
	RemoteIP    net.IP
	OutboundSPI uint32
	InboundSPI  uint32
	IfID        int
}

// OuterXFRM returns the current outer tunnel XFRM context, or ok=false if not ready.
func (s *Session) OuterXFRM() (OuterXFRMContext, bool) {
	if s == nil || s.xfrmMgr == nil || s.ChildSAOut == nil || s.ChildSAIn == nil {
		return OuterXFRMContext{}, false
	}
	if s.xfrmLocalIP == nil || s.xfrmRemoteIP == nil || s.xfrmIfID == 0 {
		return OuterXFRMContext{}, false
	}
	return OuterXFRMContext{
		LocalIP:     append(net.IP(nil), s.xfrmLocalIP...),
		RemoteIP:    append(net.IP(nil), s.xfrmRemoteIP...),
		OutboundSPI: s.ChildSAOut.SPI,
		InboundSPI:  s.ChildSAIn.SPI,
		IfID:        s.xfrmIfID,
	}, true
}
