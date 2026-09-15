package driver

import "github.com/iniwex5/netlink"

type xfrmNetlink struct {
	stateAdd     func(*netlink.XfrmState) error
	stateUpdate  func(*netlink.XfrmState) error
	stateGet     func(*netlink.XfrmState) (*netlink.XfrmState, error)
	stateDel     func(*netlink.XfrmState) error
	policyAdd    func(*netlink.XfrmPolicy) error
	policyUpdate func(*netlink.XfrmPolicy) error
	policyGet    func(*netlink.XfrmPolicy) (*netlink.XfrmPolicy, error)
	policyDel    func(*netlink.XfrmPolicy) error
}

func productionXFRM() xfrmNetlink {
	return xfrmNetlink{
		stateAdd: netlink.XfrmStateAdd, stateUpdate: netlink.XfrmStateUpdate,
		stateGet: netlink.XfrmStateGet, stateDel: netlink.XfrmStateDel,
		policyAdd: netlink.XfrmPolicyAdd, policyUpdate: netlink.XfrmPolicyUpdate,
		policyGet: netlink.XfrmPolicyGet, policyDel: netlink.XfrmPolicyDel,
	}
}
