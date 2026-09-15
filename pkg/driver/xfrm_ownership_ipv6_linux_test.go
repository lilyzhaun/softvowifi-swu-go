package driver

import (
	"errors"
	"net"
	"testing"

	"github.com/iniwex5/netlink"
	"github.com/iniwex5/netlink/nl"
	"golang.org/x/sys/unix"
)

func ipv6OuterSA(spi uint32) XFRMSAConfig {
	config := ownershipSA(spi)
	config.Src, config.Dst = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	return config
}

func ipv6OuterSP(ifid int) XFRMSPConfig {
	config := ownershipSP(ifid)
	config.TmplSrc, config.TmplDst = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	return config
}

func kernelSelectorFamily(t *testing.T, state *netlink.XfrmState) uint16 {
	t.Helper()
	request := nl.NewNetlinkRequest(nl.XFRM_MSG_GETSA, unix.NLM_F_ACK)
	query := &nl.XfrmUsersaId{Family: uint16(nl.GetIPFamily(state.Dst)), Proto: uint8(state.Proto), Spi: nl.Swap32(uint32(state.Spi))}
	query.Daddr.FromIP(state.Dst)
	request.AddData(query)
	responses, err := request.Execute(unix.NETLINK_XFRM, nl.XFRM_MSG_NEWSA)
	mustXFRM(t, err)
	if len(responses) != 1 || len(responses[0]) < nl.SizeofXfrmUsersaInfo {
		t.Fatal("GETSA did not return one complete state header")
	}
	return nl.DeserializeXfrmUsersaInfo(responses[0]).Sel.Family
}

func TestOwnershipKernelIPv6UnspecifiedSelectorCleanup(t *testing.T) {
	isolatedKernel(t)
	for _, cipher := range []string{"cbc", "aead"} {
		for _, operation := range []string{"delete", "cleanup", "flush"} {
			t.Run(cipher+"/"+operation, func(t *testing.T) {
				owner, peer := NewXFRMManager(), NewXFRMManager()
				t.Cleanup(owner.Cleanup)
				t.Cleanup(peer.Cleanup)
				config, peerConfig := ipv6OuterSA(45056), ipv6OuterSA(45057)
				if cipher == "aead" {
					config.IsAEAD, config.AeadAlgoName = true, "rfc4106(gcm(aes))"
					config.AeadKey, config.AeadICVLen = make([]byte, 20), 128
					peerConfig.IsAEAD, peerConfig.AeadAlgoName = config.IsAEAD, config.AeadAlgoName
					peerConfig.AeadKey, peerConfig.AeadICVLen = make([]byte, 20), 128
				}
				state := owner.buildXfrmState(config)
				if config.SelSrc != nil || config.SelDst != nil || config.SelProto != 0 || state.Selector != nil {
					t.Fatal("fixture is not the production unspecified-selector path")
				}
				mustXFRM(t, owner.AddSA(config))
				mustXFRM(t, peer.AddSA(peerConfig))
				mustXFRM(t, owner.AddSP(ipv6OuterSP(config.Ifid)))
				mustXFRM(t, peer.AddSP(ipv6OuterSP(peerConfig.Ifid)))
				actual, err := netlink.XfrmStateGet(state)
				mustXFRM(t, err)
				if actual.Selector == nil || actual.Selector.Src == nil || actual.Selector.Dst == nil {
					t.Fatal("GETSA selector metadata missing")
				}
				_, sourceBits := actual.Selector.Src.Mask.Size()
				_, destinationBits := actual.Selector.Dst.Mask.Size()
				t.Logf("outer_family=%d raw_sel_family=%d parsed_src=%s mask_bits=%d parsed_dst=%s mask_bits=%d",
					nl.GetIPFamily(actual.Dst), kernelSelectorFamily(t, state), actual.Selector.Src,
					sourceBits, actual.Selector.Dst, destinationBits)
				switch operation {
				case "delete":
					mustXFRM(t, owner.DelSA(config.SPI, config.Src, config.Dst, config.Proto))
					mustXFRM(t, owner.DelSP(ipv6OuterSP(config.Ifid)))
				case "cleanup":
					owner.Cleanup()
				case "flush":
					owner.FlushByIP(config.Src)
				}
				mustXFRM(t, owner.cleanupErr)
				_, err = netlink.XfrmStateGet(state)
				if !resourceAbsent(err) {
					t.Fatalf("own SA not absent after cleanup: %v", err)
				}
				_, err = netlink.XfrmStateGet(peer.buildXfrmState(peerConfig))
				mustXFRM(t, err)
				states, policies := kernelCounts(t)
				if states != 1 || policies != 1 || len(owner.UndoFuncs()) != 0 {
					t.Fatalf("after A: SA=%d SP=%d own_undo=%d", states, policies, len(owner.UndoFuncs()))
				}
				peer.Cleanup()
				mustXFRM(t, peer.cleanupErr)
				states, policies = kernelCounts(t)
				if states != 0 || policies != 0 {
					t.Fatalf("final SA=%d SP=%d", states, policies)
				}
			})
		}
	}
}

func TestOwnershipSelectorAddressFamiliesRemainDistinct(t *testing.T) {
	manager := NewXFRMManager()
	state := manager.buildXfrmState(ipv6OuterSA(49152))
	defaultSnapshot := snapshotState(state)
	state.Selector = &netlink.XfrmPolicy{
		Src: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
	}
	ipv4Snapshot := snapshotState(state)
	state.Selector = &netlink.XfrmPolicy{
		Src: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
	ipv6Snapshot := snapshotState(state)
	if ipv6Snapshot == ipv4Snapshot || ipv6Snapshot == defaultSnapshot {
		t.Fatal("ownership fingerprint erased selector address-family distinction")
	}
}

func TestOwnershipKernelIPv6CrossFamilyReplacement(t *testing.T) {
	isolatedKernel(t)
	for _, direction := range []string{"default-to-ipv6", "ipv6-to-ipv4"} {
		t.Run(direction, func(t *testing.T) {
			owner, peer := NewXFRMManager(), NewXFRMManager()
			t.Cleanup(owner.Cleanup)
			t.Cleanup(peer.Cleanup)
			config, peerConfig := ipv6OuterSA(53248), ipv6OuterSA(53249)
			ipv6Any := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			if direction == "ipv6-to-ipv4" {
				config.SelSrc, config.SelDst = ipv6Any, ipv6Any
			}
			mustXFRM(t, owner.AddSA(config))
			mustXFRM(t, peer.AddSA(peerConfig))
			mustXFRM(t, owner.AddSP(ipv6OuterSP(config.Ifid)))
			mustXFRM(t, peer.AddSP(ipv6OuterSP(peerConfig.Ifid)))
			state := owner.buildXfrmState(config)
			initialFamily := kernelSelectorFamily(t, state)
			mustXFRM(t, netlink.XfrmStateDel(state))
			config.SelSrc, config.SelDst = ipv6Any, ipv6Any
			if direction == "ipv6-to-ipv4" {
				ipv4Any := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
				config.SelSrc, config.SelDst = ipv4Any, ipv4Any
			}
			replacement := owner.buildXfrmState(config)
			mustXFRM(t, netlink.XfrmStateAdd(replacement))
			replacementFamily := kernelSelectorFamily(t, replacement)
			if initialFamily == replacementFamily {
				t.Fatal("kernel did not establish cross-family replacement")
			}
			t.Logf("replacement raw_sel_family=%d -> %d", initialFamily, replacementFamily)
			err := owner.DelSA(config.SPI, config.Src, config.Dst, config.Proto)
			if !errors.Is(err, ErrOwnershipChanged) {
				t.Fatalf("replacement delete gate: %v", err)
			}
			owner.FlushByIP(config.Src)
			if !errors.Is(owner.cleanupErr, ErrOwnershipChanged) || len(owner.states) != 1 {
				t.Fatal("ownership mismatch lost error or retry record")
			}
			states, policies := kernelCounts(t)
			if states != 2 || policies != 1 {
				t.Fatalf("replacement/peer damaged: SA=%d SP=%d", states, policies)
			}
			mustXFRM(t, netlink.XfrmStateDel(replacement))
			owner.Cleanup()
			peer.Cleanup()
			mustXFRM(t, owner.cleanupErr)
			mustXFRM(t, peer.cleanupErr)
			states, policies = kernelCounts(t)
			if states != 0 || policies != 0 || len(owner.states) != 0 {
				t.Fatalf("final SA=%d SP=%d", states, policies)
			}
		})
	}
}
