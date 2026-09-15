package driver

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"

	"github.com/iniwex5/netlink"
)

type policyKey struct {
	source, destination         string
	proto                       netlink.Proto
	sourcePort, destinationPort int
	direction                   netlink.Dir
	ifid, ifindex               int
	mark                        markIdentity
}

type ownedPolicy struct {
	generation  uint64
	index       int
	confirmErr  error
	fingerprint [32]byte
	endpoints   map[string]bool
}

func networkIdentity(network *net.IPNet) string {
	if network == nil {
		return "0.0.0.0/0"
	}
	return network.String()
}

func policyIdentity(policy *netlink.XfrmPolicy) policyKey {
	return policyKey{
		networkIdentity(policy.Src), networkIdentity(policy.Dst), policy.Proto,
		policy.SrcPort, policy.DstPort, policy.Dir, policy.Ifid, policy.Ifindex, identifyMark(policy.Mark),
	}
}

func (key policyKey) query(index int) *netlink.XfrmPolicy {
	_, source, _ := net.ParseCIDR(key.source)
	_, destination, _ := net.ParseCIDR(key.destination)
	return &netlink.XfrmPolicy{
		Src: source, Dst: destination, Proto: key.proto,
		SrcPort: key.sourcePort, DstPort: key.destinationPort, Dir: key.direction,
		Ifid: key.ifid, Ifindex: key.ifindex, Mark: key.mark.query(), Index: index,
	}
}

func policyFingerprint(policy *netlink.XfrmPolicy) [32]byte {
	value := fmt.Sprintf("%v/%d/%d", policyIdentity(policy), policy.Priority, policy.Action)
	for _, template := range policy.Tmpls {
		value += fmt.Sprintf("/%s/%s/%d/%d/%d/%d/%d", template.Src, template.Dst,
			template.Proto, template.Mode, template.Spi, template.Reqid, template.Optional)
	}
	return sha256.Sum256([]byte(value))
}

func associatePolicy(endpoints map[string]bool, policy *netlink.XfrmPolicy) {
	if policy.Src != nil {
		endpoints[policy.Src.IP.String()] = true
	}
	if policy.Dst != nil {
		endpoints[policy.Dst.IP.String()] = true
	}
	for _, template := range policy.Tmpls {
		endpoints[template.Src.String()] = true
		endpoints[template.Dst.String()] = true
	}
}

func (x *XFRMManager) addOwnedPolicy(policy *netlink.XfrmPolicy) error {
	key := policyIdentity(policy)
	if x.policies[key] != nil {
		return x.updateOwnedPolicy(policy)
	}
	if err := x.ops.policyAdd(policy); err != nil {
		return fmt.Errorf("add XFRM SP: %w", err)
	}
	record := &ownedPolicy{generation: x.nextGeneration(), fingerprint: policyFingerprint(policy), endpoints: make(map[string]bool)}
	associatePolicy(record.endpoints, policy)
	x.policies[key] = record
	actual, err := x.ops.policyGet(key.query(0))
	if err == nil {
		switch {
		case actual.Index <= 0:
			err = ErrOwnershipUnconfirmed
		case policyIdentity(actual) != key || policyFingerprint(actual) != record.fingerprint:
			err = ErrOwnershipChanged
		default:
			record.index = actual.Index
		}
	}
	if err != nil {
		record.confirmErr = err
		return ownershipFailure("confirm SP", errors.Join(ErrOwnershipUnconfirmed, err))
	}
	return nil
}

func (x *XFRMManager) checkOwnedPolicy(key policyKey, record *ownedPolicy) error {
	if record.index == 0 {
		return errors.Join(ErrOwnershipUnconfirmed, record.confirmErr)
	}
	actual, err := x.ops.policyGet(key.query(record.index))
	if err != nil {
		return err
	}
	if policyIdentity(actual) != key || policyFingerprint(actual) != record.fingerprint ||
		actual.Index != record.index {
		return ErrOwnershipChanged
	}
	return nil
}

func (x *XFRMManager) deleteOwnedPolicy(key policyKey, generation uint64) error {
	record := x.policies[key]
	if record == nil || (generation != 0 && generation != record.generation) {
		return nil
	}
	err := x.checkOwnedPolicy(key, record)
	if err == nil {
		err = x.ops.policyDel(key.query(record.index))
	}
	if err != nil && (errors.Is(err, ErrOwnershipUnconfirmed) || !resourceAbsent(err)) {
		return ownershipFailure("delete SP", err)
	}
	delete(x.policies, key)
	return nil
}

func (x *XFRMManager) updateOwnedPolicy(policy *netlink.XfrmPolicy) error {
	key := policyIdentity(policy)
	record := x.policies[key]
	if record == nil {
		return ownershipFailure("update SP", ErrXFRMNotOwned)
	}
	if err := x.checkOwnedPolicy(key, record); err != nil {
		return ownershipFailure("update SP", err)
	}
	policy.Index = record.index
	if err := x.ops.policyUpdate(policy); err != nil {
		return fmt.Errorf("update XFRM SP: %w", err)
	}
	record.fingerprint = policyFingerprint(policy)
	associatePolicy(record.endpoints, policy)
	return nil
}
