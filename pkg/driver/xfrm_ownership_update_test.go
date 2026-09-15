package driver

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestOwnershipRekeyAndMovedEndpoints(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa, policy := ownershipSA(256), ownershipSP(256)
	sa.EncapType = netlink.XFRM_ENCAP_ESPINUDP
	sa.EncapSrcPort, sa.EncapDstPort = 4500, 4500
	mustXFRM(t, owner.AddSA(sa))
	mustXFRM(t, owner.AddSP(policy))
	initialUndos := owner.UndoFuncs()
	for index := 0; index < 20; index++ {
		policy.TmplSPI = 300 + index
		mustXFRM(t, owner.AddSP(policy))
	}
	if len(owner.UndoFuncs()) != 2 {
		t.Fatal("policy rekey accumulated callbacks")
	}
	sa.EncapSrcPort, sa.EncapDstPort = 4600, 4500
	mustXFRM(t, owner.UpdateSA(sa))
	policy.TmplSrc = net.ParseIP("192.0.2.9")
	mustXFRM(t, owner.UpdateSP(policy))
	for _, undo := range initialUndos {
		mustXFRM(t, undo())
	}
	owner.FlushByIP(net.ParseIP("192.0.2.1"))
	mustXFRM(t, owner.cleanupErr)
	if len(kernel.states)+len(kernel.policies) != 0 {
		t.Fatal("rekey/move leaked resources")
	}
}

func TestOwnershipKeyMigrationRejectedBeforeMutation(t *testing.T) {
	kernel := newTestKernel()
	owner, peer := kernel.manager(t), kernel.manager(t)
	sa := ownershipSA(256)
	mustXFRM(t, owner.AddSA(sa))
	sa.Dst = net.ParseIP("192.0.2.8")
	mustXFRM(t, peer.AddSA(sa))
	err := owner.UpdateSA(sa)
	if !errors.Is(err, ErrXFRMNotOwned) || kernel.updates != 0 || len(kernel.states) != 2 {
		t.Fatal("destination migration adopted foreign key")
	}
	policy := ownershipSP(256)
	err = owner.UpdateSP(policy)
	if !errors.Is(err, ErrXFRMNotOwned) || kernel.updates != 0 {
		t.Fatal("unknown policy update was accepted")
	}
}

func TestOwnershipExternalReplacementBlocksEveryMutation(t *testing.T) {
	for _, operation := range []string{"delete", "undo", "cleanup", "flush", "update", "add-policy"} {
		t.Run(operation, func(t *testing.T) {
			kernel := newTestKernel()
			owner := kernel.manager(t)
			sa, policy := ownershipSA(256), ownershipSP(256)
			mustXFRM(t, owner.AddSA(sa))
			mustXFRM(t, owner.AddSP(policy))
			kernel.states[testSAKey(owner.buildXfrmState(sa))].Ifid++
			kernel.policies[testSPKey(owner.buildXfrmPolicy(policy))].Priority++
			var err error
			switch operation {
			case "delete":
				err = errors.Join(owner.DelSA(sa.SPI, sa.Src, sa.Dst, sa.Proto), owner.DelSP(policy))
			case "undo":
				for _, undo := range owner.UndoFuncs() {
					err = errors.Join(err, undo())
				}
			case "cleanup":
				owner.Cleanup()
				err = owner.cleanupErr
			case "flush":
				owner.FlushByIP(sa.Src)
				err = owner.cleanupErr
			case "update":
				err = errors.Join(owner.UpdateSA(sa), owner.UpdateSP(policy))
			case "add-policy":
				err = owner.AddSP(policy)
			}
			if !errors.Is(err, ErrOwnershipChanged) || kernel.deletes != 0 || kernel.updates != 0 {
				t.Fatalf("replacement gate failed: %v", err)
			}
		})
	}
}

func TestOwnershipCountersDoNotInvalidateSnapshot(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa := ownershipSA(256)
	mustXFRM(t, owner.AddSA(sa))
	state := kernel.states[testSAKey(owner.buildXfrmState(sa))]
	state.Statistics.Bytes = 999
	state.Replay = &netlink.XfrmReplayState{Seq: 12, OSeq: 15}
	owner.Cleanup()
	mustXFRM(t, owner.cleanupErr)
	if len(kernel.states) != 0 {
		t.Fatal("traffic counters prevented cleanup")
	}
}

func TestOwnershipConcurrentUpdateAndCleanup(t *testing.T) {
	kernel := newTestKernel()
	owner := kernel.manager(t)
	sa, policy := ownershipSA(256), ownershipSP(256)
	mustXFRM(t, owner.AddSA(sa))
	mustXFRM(t, owner.AddSP(policy))
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for iteration := 0; iteration < 10; iteration++ {
				err := owner.UpdateSA(sa)
				if err != nil && !errors.Is(err, ErrXFRMNotOwned) {
					t.Error(err)
				}
				err = owner.UpdateSP(policy)
				if err != nil && !errors.Is(err, ErrXFRMNotOwned) {
					t.Error(err)
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		owner.Cleanup()
	}()
	close(start)
	workers.Wait()
	owner.Cleanup()
	mustXFRM(t, owner.cleanupErr)
	if len(kernel.states)+len(kernel.policies) != 0 {
		t.Fatal("serialized cleanup leaked resources")
	}
}
