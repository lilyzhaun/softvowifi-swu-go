package driver

import (
	"encoding/json"
	"fmt"
	"sync"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

type testKernel struct {
	mu                sync.Mutex
	states            map[string]*netlink.XfrmState
	policies          map[string]*netlink.XfrmPolicy
	nextIndex         int
	deletes, updates  int
	deleteErr, getErr error
	authTruncDefault  int
}

func testCopy[T any](t *testing.T, value *T) *T {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode synthetic resource")
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal("decode synthetic resource")
	}
	return &result
}

func testSAKey(state *netlink.XfrmState) string {
	return fmt.Sprintf("%s/%d/%d/%v", state.Dst, state.Spi, state.Proto, state.Mark)
}

func (kernel *testKernel) resolveDefaults(state *netlink.XfrmState) {
	if kernel.authTruncDefault != 0 && state.Auth != nil && state.Auth.TruncateLen == 0 {
		state.Auth.TruncateLen = kernel.authTruncDefault
	}
}

func testSPKey(policy *netlink.XfrmPolicy) string {
	return fmt.Sprintf("%s/%s/%d/%d/%d/%d/%d/%v", policy.Src, policy.Dst,
		policy.Dir, policy.Proto, policy.SrcPort, policy.DstPort, policy.Ifid, policy.Mark)
}

func newTestKernel() *testKernel {
	return &testKernel{states: make(map[string]*netlink.XfrmState), policies: make(map[string]*netlink.XfrmPolicy)}
}

func (kernel *testKernel) manager(t *testing.T) *XFRMManager {
	t.Helper()
	manager := NewXFRMManager()
	manager.ops = xfrmNetlink{
		stateAdd: func(state *netlink.XfrmState) error {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			key := testSAKey(state)
			if kernel.states[key] != nil {
				return syscall.EEXIST
			}
			stored := testCopy(t, state)
			kernel.resolveDefaults(stored)
			kernel.states[key] = stored
			return nil
		},
		stateGet: func(state *netlink.XfrmState) (*netlink.XfrmState, error) {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			if kernel.getErr != nil {
				return nil, kernel.getErr
			}
			found := kernel.states[testSAKey(state)]
			if found == nil {
				return nil, syscall.ESRCH
			}
			return testCopy(t, found), nil
		},
		stateDel: func(state *netlink.XfrmState) error {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.deletes++
			if kernel.deleteErr != nil {
				return kernel.deleteErr
			}
			key := testSAKey(state)
			if kernel.states[key] == nil {
				return syscall.ESRCH
			}
			delete(kernel.states, key)
			return nil
		},
		stateUpdate: func(state *netlink.XfrmState) error {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.updates++
			key := testSAKey(state)
			if kernel.states[key] == nil {
				return syscall.ESRCH
			}
			stored := testCopy(t, state)
			kernel.resolveDefaults(stored)
			kernel.states[key] = stored
			return nil
		},
		policyAdd: func(policy *netlink.XfrmPolicy) error {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			key := testSPKey(policy)
			if kernel.policies[key] != nil {
				return syscall.EEXIST
			}
			kernel.nextIndex += 8
			copy := testCopy(t, policy)
			copy.Index = kernel.nextIndex + int(policy.Dir)
			kernel.policies[key] = copy
			return nil
		},
		policyGet: func(policy *netlink.XfrmPolicy) (*netlink.XfrmPolicy, error) {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			if kernel.getErr != nil {
				return nil, kernel.getErr
			}
			found := kernel.lookupPolicy(policy)
			if found == nil {
				return nil, syscall.ENOENT
			}
			return testCopy(t, found), nil
		},
		policyDel: func(policy *netlink.XfrmPolicy) error {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.deletes++
			if kernel.deleteErr != nil {
				return kernel.deleteErr
			}
			found := kernel.lookupPolicy(policy)
			if found == nil {
				return syscall.ENOENT
			}
			delete(kernel.policies, testSPKey(found))
			return nil
		},
		policyUpdate: func(policy *netlink.XfrmPolicy) error {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.updates++
			copy := testCopy(t, policy)
			if found := kernel.lookupPolicy(policy); found != nil {
				copy.Index = found.Index
			} else {
				kernel.nextIndex += 8
				copy.Index = kernel.nextIndex + int(policy.Dir)
			}
			kernel.policies[testSPKey(policy)] = copy
			return nil
		},
	}
	return manager
}

func (kernel *testKernel) lookupPolicy(query *netlink.XfrmPolicy) *netlink.XfrmPolicy {
	if query.Index == 0 {
		return kernel.policies[testSPKey(query)]
	}
	for _, policy := range kernel.policies {
		if policy.Index == query.Index && policy.Dir == query.Dir && policy.Ifid == query.Ifid {
			return policy
		}
	}
	return nil
}
