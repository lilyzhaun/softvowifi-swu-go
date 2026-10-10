package swu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/1239t/swu-go/pkg/ikev2"
)

var errInitialChild = errors.New("invalid initial Child SA transaction")

// Static invariant names only: never include addresses, identities, payloads
// or key material in rejection diagnostics.
func initialChildFailure(reason string) error {
	return fmt.Errorf("initial Child %s: %w", reason, errInitialChild)
}

type initialChildSelection struct {
	proposal    *ikev2.Proposal
	cp          *ikev2.CPConfig
	tsi, tsr    []*ikev2.TrafficSelector
	encr, integ uint16
	keyBits     int
}

func (s *Session) snapshotInitialChildRequest(cp *ikev2.EncryptedPayloadCP, sa *ikev2.EncryptedPayloadSA, tsi, tsr *ikev2.EncryptedPayloadTS) error {
	packet := ikev2.NewIKEPacket()
	packet.Payloads = []ikev2.Payload{cp, sa, tsi, tsr}
	raw, err := packet.Encode()
	if err != nil {
		return err
	}
	s.initialChildRequest = raw
	return nil
}

func (s *Session) selectInitialChild(payloads []ikev2.Payload) (initialChildSelection, error) {
	var empty initialChildSelection
	if len(s.initialChildRequest) == 0 || s.childSPI == 0 {
		return empty, initialChildFailure("request snapshot")
	}
	request, err := ikev2.DecodePacket(s.initialChildRequest)
	if err != nil {
		return empty, err
	}
	var selectedSA, offeredSA *ikev2.EncryptedPayloadSA
	var selectedCP, requestedCP *ikev2.EncryptedPayloadCP
	var selectedI, selectedR, offeredI, offeredR *ikev2.EncryptedPayloadTS
	for _, payload := range request.Payloads {
		switch p := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			offeredSA = p
		case *ikev2.EncryptedPayloadCP:
			requestedCP = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				offeredI = p
			} else {
				offeredR = p
			}
		}
	}
	for _, payload := range payloads {
		switch p := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			if selectedSA != nil {
				return empty, initialChildFailure("duplicate SA")
			}
			selectedSA = p
		case *ikev2.EncryptedPayloadCP:
			// RFC7296 2.19: CFG_REPLY precedes the matching SA payload.
			if selectedCP != nil || selectedSA != nil {
				return empty, initialChildFailure("CP count/order")
			}
			selectedCP = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				if selectedI != nil {
					return empty, initialChildFailure("duplicate TSi")
				}
				selectedI = p
			} else {
				if selectedR != nil {
					return empty, initialChildFailure("duplicate TSr")
				}
				selectedR = p
			}
		case *ikev2.EncryptedPayloadKE:
			// The initial AUTH1 offers no additional DH transform or KE.
			return empty, initialChildFailure("unoffered KE")
		}
	}
	if selectedSA == nil || len(selectedSA.Proposals) != 1 || offeredSA == nil || requestedCP == nil || selectedCP == nil || selectedI == nil || selectedR == nil {
		return empty, initialChildFailure("required SA/CP/TS")
	}
	p := selectedSA.Proposals[0]
	if p.ProtocolID != ikev2.ProtoESP || len(p.SPI) != 4 || binary.BigEndian.Uint32(p.SPI) == 0 {
		return empty, initialChildFailure("protocol/SPI")
	}
	var offered *ikev2.Proposal
	for _, candidate := range offeredSA.Proposals {
		if candidate.ProposalNum == p.ProposalNum {
			offered = candidate
		}
	}
	if offered == nil {
		return empty, initialChildFailure("proposal number")
	}
	if len(p.Transforms) != len(offered.Transforms) {
		return empty, initialChildFailure("transform count")
	}
	selection := initialChildSelection{proposal: p}
	seen := map[ikev2.TransformType]bool{}
	for _, transform := range p.Transforms {
		if seen[transform.Type] {
			return empty, initialChildFailure("duplicate transform")
		}
		seen[transform.Type] = true
		matched := false
		for _, original := range offered.Transforms {
			if transform.Type != original.Type || transform.ID != original.ID || len(transform.Attributes) != len(original.Attributes) {
				continue
			}
			matched = true
			for i, attr := range transform.Attributes {
				other := original.Attributes[i]
				if attr.Type != other.Type || attr.Val != other.Val || !bytes.Equal(attr.Value, other.Value) {
					matched = false
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return empty, initialChildFailure("transform/attribute not offered")
		}
		switch transform.Type {
		case ikev2.TransformTypeEncr:
			selection.encr = uint16(transform.ID)
			selection.keyBits = int(transform.Attributes[0].Val)
		case ikev2.TransformTypeInteg:
			selection.integ = uint16(transform.ID)
		case ikev2.TransformTypeESN:
			// All six original complete offers explicitly select NO_ESN.
			if transform.ID != 0 {
				return empty, initialChildFailure("unoffered ESN")
			}
		default:
			return empty, initialChildFailure("unoffered transform type")
		}
	}
	if !seen[ikev2.TransformTypeEncr] || !seen[ikev2.TransformTypeESN] {
		return empty, initialChildFailure("mandatory transform")
	}
	if err := validateInitialCP(selectedCP, requestedCP); err != nil {
		return empty, err
	}
	selection.cp = ikev2.ParseCPConfig(selectedCP)
	if err := validateInitialTS(selectedI, offeredI); err != nil {
		return empty, err
	}
	if err := validateInitialTS(selectedR, offeredR); err != nil {
		return empty, err
	}
	// RFC7296 3.15.4 permits a partial allocation of a dual-stack request.
	// All wire selectors were validated above; inactive families never become
	// runtime selectors, routes or policies. Assigned families still require
	// an address bound to TSi and a compatible TSr in the same transaction.
	var inactiveReason string
	for _, ts := range selectedI.TrafficSelectors {
		addresses := selection.cp.IPv4Addresses
		family := "IPv4"
		if ts.TSType == ikev2.TS_IPV6_ADDR_RANGE {
			addresses = selection.cp.IPv6Addresses
			family = "IPv6"
		}
		if len(addresses) == 0 {
			inactiveReason = family + " without allocation"
			continue
		}
		bound := false
		for _, address := range addresses {
			if ipInSelector(address, ts) {
				bound = true
				break
			}
		}
		if !bound {
			return empty, initialChildFailure("TSi assigned address (" + family + " outside allocation)")
		}
		paired := false
		for _, remote := range selectedR.TrafficSelectors {
			if selectorsShareFamilyProtocol(ts, remote) {
				paired = true
				break
			}
		}
		if !paired {
			return empty, initialChildFailure("TSi/TSr family/protocol intersection")
		}
		selection.tsi = append(selection.tsi, ts)
	}
	if len(selection.tsi) == 0 {
		return empty, initialChildFailure("TSi assigned address (" + inactiveReason + ")")
	}
	for _, remote := range selectedR.TrafficSelectors {
		for _, local := range selection.tsi {
			if selectorsShareFamilyProtocol(local, remote) {
				selection.tsr = append(selection.tsr, remote)
				break
			}
		}
	}
	var v4, v6 bool
	for _, ts := range selection.tsi {
		if ts.TSType == ikev2.TS_IPV4_ADDR_RANGE {
			v4 = true
		} else {
			v6 = true
		}
	}
	if !v4 {
		selection.cp.IPv4Addresses = nil
		selection.cp.IPv4DNS = nil
		selection.cp.IPv4PCSCF = nil
	}
	if !v6 {
		selection.cp.IPv6Addresses = nil
		selection.cp.IPv6DNS = nil
		selection.cp.IPv6PCSCF = nil
		selection.cp.IPv6Prefix = 0
	}
	return selection, nil
}

func selectorsShareFamilyProtocol(a, b *ikev2.TrafficSelector) bool {
	return a.TSType == b.TSType && (a.IPProtocol == 0 || b.IPProtocol == 0 || a.IPProtocol == b.IPProtocol)
}

func validateInitialCP(reply, request *ikev2.EncryptedPayloadCP) error {
	if reply.CFGType != ikev2.CFG_REPLY || request.CFGType != ikev2.CFG_REQUEST {
		return initialChildFailure("CP type")
	}
	requested := map[uint16]int{}
	for _, attr := range request.Attributes {
		requested[attr.Type]++
	}
	counts := map[uint16]int{}
	for _, attr := range reply.Attributes {
		counts[attr.Type]++
		size := len(attr.Value)
		switch attr.Type {
		case ikev2.INTERNAL_IP4_ADDRESS, ikev2.INTERNAL_IP6_ADDRESS:
			expected := 4
			if attr.Type == ikev2.INTERNAL_IP6_ADDRESS {
				expected = 17
			}
			if size != expected {
				return initialChildFailure("CP address length")
			}
			if counts[attr.Type] > requested[attr.Type] {
				return initialChildFailure("CP address count")
			}
			ipBytes := expected
			if expected == 17 {
				ipBytes = 16
			}
			ip := net.IP(attr.Value[:ipBytes])
			if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
				return initialChildFailure("CP address scope")
			}
			if expected == 17 && (ip.To4() != nil || attr.Value[16] > 128) {
				return initialChildFailure("CP IPv6 prefix/family")
			}
		case ikev2.INTERNAL_IP4_DNS, ikev2.P_CSCF_IP4_ADDRESS, ikev2.INTERNAL_IP4_NBNS, ikev2.INTERNAL_IP4_DHCP:
			if size != 0 && size != 4 {
				return initialChildFailure("CP IPv4 server length")
			}
		case ikev2.INTERNAL_IP6_DNS, ikev2.P_CSCF_IP6_ADDRESS, ikev2.ASSIGNED_PCSCF_IP6_ADDRESS, ikev2.INTERNAL_IP6_DHCP:
			if size != 0 && size != 16 {
				return initialChildFailure("CP IPv6 server length")
			}
		case ikev2.INTERNAL_IP4_NETMASK:
			if size != 4 || counts[attr.Type] > 1 {
				return initialChildFailure("CP netmask shape")
			}
			_, bits := net.IPMask(attr.Value).Size()
			if bits != 32 {
				return initialChildFailure("CP netmask noncontiguous")
			}
		case ikev2.INTERNAL_IP4_SUBNET:
			if size != 0 && size != 8 {
				return initialChildFailure("CP subnet length")
			}
		case ikev2.SUPPORTED_ATTRIBUTES:
			if size%2 != 0 || counts[attr.Type] > 1 {
				return initialChildFailure("CP supported attributes shape")
			}
		case ikev2.APPLICATION_VERSION:
			if counts[attr.Type] > 1 {
				return initialChildFailure("CP application version count")
			}
		default:
			// RFC7296 permits unrequested attributes; unsupported ones are not
			// consumed into local configuration, so no guessed format is applied.
		}
	}
	if counts[ikev2.INTERNAL_IP4_ADDRESS]+counts[ikev2.INTERNAL_IP6_ADDRESS] == 0 {
		return initialChildFailure("CP missing address")
	}
	if counts[ikev2.INTERNAL_IP4_NETMASK] > 0 && counts[ikev2.INTERNAL_IP4_ADDRESS] == 0 {
		return initialChildFailure("CP netmask without address")
	}
	return nil
}

func validateInitialTS(selected, offered *ikev2.EncryptedPayloadTS) error {
	if offered == nil || len(selected.TrafficSelectors) == 0 {
		return initialChildFailure("TS empty/request")
	}
	for _, ts := range selected.TrafficSelectors {
		if ts.StartPort > ts.EndPort || bytes.Compare(ts.StartAddr, ts.EndAddr) > 0 {
			return initialChildFailure("TS reversed range")
		}
		matched := false
		for _, original := range offered.TrafficSelectors {
			if ts.TSType == original.TSType && (original.IPProtocol == 0 || ts.IPProtocol == original.IPProtocol) && ts.StartPort >= original.StartPort && ts.EndPort <= original.EndPort && bytes.Compare(ts.StartAddr, original.StartAddr) >= 0 && bytes.Compare(ts.EndAddr, original.EndAddr) <= 0 {
				matched = true
				break
			}
		}
		if !matched {
			return initialChildFailure("TS outside request")
		}
	}
	return nil
}

func ipInSelector(ip net.IP, ts *ikev2.TrafficSelector) bool {
	if ts.TSType == ikev2.TS_IPV4_ADDR_RANGE {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	return len(ip) == len(ts.StartAddr) && bytes.Compare(ip, ts.StartAddr) >= 0 && bytes.Compare(ip, ts.EndAddr) <= 0
}
