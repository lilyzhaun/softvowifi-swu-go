package driver

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipPR7RekeyCallOrderPartialMatrix(t *testing.T) {
	for failure := -1; failure < 6; failure++ {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			kernel := newTestKernel()
			owner, peer := kernel.manager(t), kernel.manager(t)
			oldOut, oldIn := ownershipSA(256), ownershipSA(257)
			mustXFRM(t, owner.AddSA(oldOut))
			mustXFRM(t, owner.AddSA(oldIn))
			policies := make([]XFRMSPConfig, 4)
			for index := range policies {
				policies[index] = ownershipSP(256)
				policies[index].SrcPort = 40000 + index
				mustXFRM(t, owner.AddSP(policies[index]))
			}
			mustXFRM(t, peer.AddSA(ownershipSA(512)))
			mustXFRM(t, peer.AddSP(ownershipSP(512)))
			addState, updatePolicy := owner.ops.stateAdd, owner.ops.policyUpdate
			operation := 0
			owner.ops.stateAdd = func(state *netlink.XfrmState) error {
				current := operation
				operation++
				if current == failure {
					return syscall.EIO
				}
				return addState(state)
			}
			owner.ops.policyUpdate = func(policy *netlink.XfrmPolicy) error {
				current := operation
				operation++
				if current == failure {
					return syscall.EIO
				}
				return updatePolicy(policy)
			}
			nextOut, nextIn := ownershipSA(258), ownershipSA(259)
			rekey := func() error {
				if err := owner.AddSA(nextOut); err != nil {
					return err
				}
				if err := owner.AddSA(nextIn); err != nil {
					return errors.Join(err, owner.DelSA(nextOut.SPI, nextOut.Src, nextOut.Dst, nextOut.Proto))
				}
				for _, policy := range policies {
					policy.TmplSPI = int(nextOut.SPI)
					if err := owner.AddSP(policy); err != nil {
						return err
					}
				}
				if err := owner.DelSA(oldOut.SPI, oldOut.Src, oldOut.Dst, oldOut.Proto); err != nil {
					return err
				}
				return owner.DelSA(oldIn.SPI, oldIn.Src, oldIn.Dst, oldIn.Proto)
			}
			err := rekey()
			if failure == -1 {
				mustXFRM(t, err)
			} else if !errors.Is(err, syscall.EIO) {
				t.Fatalf("partial operation: %v", err)
			}
			wantStates := 3
			if failure >= 2 {
				wantStates = 5
			}
			if len(kernel.states) != wantStates {
				t.Fatalf("partial SA count=%d want=%d", len(kernel.states), wantStates)
			}
			owner.Cleanup()
			mustXFRM(t, owner.cleanupErr)
			if len(kernel.states) != 1 || len(kernel.policies) != 1 {
				t.Fatal("PR7-style rollback/cleanup violated peer isolation")
			}
		})
	}
}
