package driver

import (
	"net"

	"github.com/iniwex5/netlink"
)

func (x *XFRMManager) buildXfrmState(cfg XFRMSAConfig) *netlink.XfrmState {
	replayWindow := cfg.ReplayWindow
	if replayWindow <= 0 && cfg.SADir != netlink.XFRM_SA_DIR_OUT {
		replayWindow = 32
	}
	state := &netlink.XfrmState{
		Src:          cfg.Src,
		Dst:          cfg.Dst,
		Proto:        cfg.Proto,
		Mode:         cfg.Mode,
		Spi:          int(cfg.SPI),
		Reqid:        cfg.Reqid,
		ReplayWindow: replayWindow,
		Ifid:         cfg.Ifid,
		AFUnspec:     cfg.Mode == netlink.XFRM_MODE_TUNNEL,
		ESN:          cfg.ESN,
		SADir:        cfg.SADir,
		Limits: netlink.XfrmStateLimits{
			TimeSoft: cfg.TimeLimitSoft,
			TimeHard: cfg.TimeLimitHard,
		},
	}
	if cfg.IsAEAD {
		state.Aead = &netlink.XfrmStateAlgo{
			Name: cfg.AeadAlgoName, Key: cfg.AeadKey, ICVLen: cfg.AeadICVLen,
		}
	} else {
		if cfg.CryptAlgoName != "" {
			state.Crypt = &netlink.XfrmStateAlgo{Name: cfg.CryptAlgoName, Key: cfg.CryptKey}
		}
		if cfg.AuthAlgoName != "" {
			state.Auth = &netlink.XfrmStateAlgo{
				Name: cfg.AuthAlgoName, Key: cfg.AuthKey, TruncateLen: cfg.AuthTruncLen,
			}
		}
	}
	if cfg.EncapType != 0 {
		state.Encap = &netlink.XfrmStateEncap{
			Type: cfg.EncapType, SrcPort: cfg.EncapSrcPort, DstPort: cfg.EncapDstPort,
		}
	}
	if cfg.SelSrc != nil || cfg.SelDst != nil || cfg.SelProto != 0 {
		state.Selector = &netlink.XfrmPolicy{
			Src: cfg.SelSrc, Dst: cfg.SelDst,
			Proto: cfg.SelProto, SrcPort: cfg.SelSrcPort, DstPort: cfg.SelDstPort,
		}
	}
	return state
}

func (x *XFRMManager) buildXfrmPolicy(cfg XFRMSPConfig) *netlink.XfrmPolicy {
	policy := &netlink.XfrmPolicy{
		Src:      cfg.Src,
		Dst:      cfg.Dst,
		Dir:      cfg.Dir,
		Ifid:     cfg.Ifid,
		Proto:    cfg.Proto,
		SrcPort:  cfg.SrcPort,
		DstPort:  cfg.DstPort,
		Priority: cfg.Priority,
	}
	tmpls := cfg.Tmpls
	if len(tmpls) == 0 && (cfg.TmplSrc != nil || cfg.TmplDst != nil || cfg.TmplProto != 0) {
		tmpls = []XFRMPolicyTmpl{{
			Src: cfg.TmplSrc, Dst: cfg.TmplDst,
			Proto: cfg.TmplProto, Mode: cfg.TmplMode,
			SPI: cfg.TmplSPI, Reqid: cfg.TmplReqid,
		}}
	}
	policy.Tmpls = make([]netlink.XfrmPolicyTmpl, 0, len(tmpls))
	for _, t := range tmpls {
		policy.Tmpls = append(policy.Tmpls, netlink.XfrmPolicyTmpl{
			Src: preferIPv4(t.Src), Dst: preferIPv4(t.Dst),
			Proto: t.Proto, Mode: t.Mode, Spi: t.SPI, Reqid: t.Reqid,
		})
	}
	return policy
}

func preferIPv4(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
