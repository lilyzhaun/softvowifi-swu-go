package swu

import (
	"errors"
	"fmt"
	"net"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/iniwex5/netlink"
)

type childRekeyXFRMOps interface {
	AddSA(driver.XFRMSAConfig) error
	DelSA(uint32, net.IP, net.IP, netlink.Proto) error
	AddSP(driver.XFRMSPConfig) error
}

type childSARekey struct {
	out, in *ipsec.SecurityAssociation
	encrID  uint16
	keyBits int
}

func (s *Session) rekeyXFRM(ops childRekeyXFRMOps, next childSARekey, old [2]uint32) error {
	if ops == nil {
		return nil
	}
	localIP, remoteIP := s.xfrmLocalIP, s.xfrmRemoteIP
	isAEAD := driver.IsAEADAlgorithm(next.encrID)
	out := driver.XFRMSAConfig{
		Src: localIP, Dst: remoteIP, SPI: next.out.SPI,
		Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
		IsAEAD: isAEAD, EncapType: netlink.XFRM_ENCAP_ESPINUDP,
		EncapSrcPort: s.xfrmLocalPort, EncapDstPort: s.xfrmRemotePort,
		Ifid: s.xfrmIfID, ReplayWindow: s.cfg.ReplayWindow,
		SADir: netlink.XFRM_SA_DIR_OUT, ESN: s.childESN,
	}
	in := driver.XFRMSAConfig{
		Src: remoteIP, Dst: localIP, SPI: next.in.SPI,
		Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
		IsAEAD: isAEAD, EncapType: netlink.XFRM_ENCAP_ESPINUDP,
		EncapSrcPort: s.xfrmRemotePort, EncapDstPort: s.xfrmLocalPort,
		Ifid: s.xfrmIfID, ReplayWindow: s.cfg.ReplayWindow,
		SADir: netlink.XFRM_SA_DIR_IN, ESN: s.childESN,
	}
	if isAEAD {
		info, err := driver.IKEv2AlgToXFRMAead(next.encrID, next.keyBits)
		if err != nil {
			return fmt.Errorf("Rekey 映射 AEAD 算法失败: %w", err)
		}
		out.AeadAlgoName, in.AeadAlgoName = info.Name, info.Name
		out.AeadKey, in.AeadKey = next.out.EncryptionKey, next.in.EncryptionKey
		out.AeadICVLen, in.AeadICVLen = info.ICVBits, info.ICVBits
	} else {
		info, err := driver.IKEv2AlgToXFRMCrypt(next.encrID, next.keyBits)
		if err != nil {
			return fmt.Errorf("Rekey 映射加密算法失败: %w", err)
		}
		out.CryptAlgoName, in.CryptAlgoName = info.Name, info.Name
		out.CryptKey, in.CryptKey = next.out.EncryptionKey, next.in.EncryptionKey
		if s.childIntegID != 0 {
			auth, err := driver.IKEv2AlgToXFRMAuth(s.childIntegID)
			if err != nil {
				return fmt.Errorf("Rekey 映射完整性算法失败: %w", err)
			}
			out.AuthAlgoName, in.AuthAlgoName = auth.Name, auth.Name
			out.AuthKey, in.AuthKey = next.out.IntegrityKey, next.in.IntegrityKey
			out.AuthTruncLen, in.AuthTruncLen = auth.TruncateBits, auth.TruncateBits
		}
	}
	allIPv4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	allIPv6 := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	policies := make([]driver.XFRMSPConfig, 0, 4)
	for _, src := range []*net.IPNet{allIPv4, allIPv6} {
		policies = append(policies, driver.XFRMSPConfig{
			Src: src, Dst: src, Dir: netlink.XFRM_DIR_OUT,
			Priority: driver.OuterBroadPolicyPriority,
			TmplSrc:  localIP, TmplDst: remoteIP,
			TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
			TmplSPI: int(next.out.SPI), Ifid: s.xfrmIfID,
		})
	}
	for _, src := range []*net.IPNet{allIPv4, allIPv6} {
		policies = append(policies, driver.XFRMSPConfig{
			Src: src, Dst: src, Dir: netlink.XFRM_DIR_IN,
			Priority: driver.OuterBroadPolicyPriority,
			TmplSrc:  remoteIP, TmplDst: localIP,
			TmplProto: netlink.XFRM_PROTO_ESP, TmplMode: netlink.XFRM_MODE_TUNNEL,
			TmplSPI: int(next.in.SPI), Ifid: s.xfrmIfID,
		})
	}
	if err := ops.AddSA(out); err != nil {
		return fmt.Errorf("Rekey 安装出站 SA 失败: %w", err)
	}
	if err := ops.AddSA(in); err != nil {
		installErr := fmt.Errorf("Rekey 安装入站 SA 失败: %w", err)
		if rollbackErr := ops.DelSA(out.SPI, out.Src, out.Dst, out.Proto); rollbackErr != nil {
			return errors.Join(installErr, fmt.Errorf("Rekey 回滚新出站 SA 失败，残留待会话清理: %w", rollbackErr))
		}
		return installErr
	}
	for index, policy := range policies {
		if err := ops.AddSP(policy); err != nil {
			return fmt.Errorf("Rekey 更新策略 %d 失败，保留新旧 SA 待会话清理: %w", index, err)
		}
	}
	if err := ops.DelSA(old[0], localIP, remoteIP, netlink.XFRM_PROTO_ESP); err != nil {
		return fmt.Errorf("Rekey 删除旧出站 SA 失败，残留待会话清理: %w", err)
	}
	if err := ops.DelSA(old[1], remoteIP, localIP, netlink.XFRM_PROTO_ESP); err != nil {
		return fmt.Errorf("Rekey 删除旧入站 SA 失败，旧出站已删除，残留待会话清理: %w", err)
	}
	return nil
}
