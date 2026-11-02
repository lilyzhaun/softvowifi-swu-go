package swu

import (
	"context"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/iniwex5/netlink"
)

type ChildSAPairProof struct {
	Inbound  driver.OwnedSAProof `json:"inbound"`
	Outbound driver.OwnedSAProof `json:"outbound"`
}

type PreviousChildSAProof struct {
	State string            `json:"state"`
	Phase string            `json:"phase,omitempty"`
	Pair  *ChildSAPairProof `json:"pair,omitempty"`
}

// ChildSAProof contains no tuple, credential, key hash or raw error. Current
// verification and the most recently observed old pair are independent facts.
type ChildSAProof struct {
	State    string                `json:"state"`
	Current  *ChildSAPairProof     `json:"current,omitempty"`
	Previous *PreviousChildSAProof `json:"previous,omitempty"`
}

type childProofReader interface {
	ReadOwnedSAProof(context.Context, driver.OwnedSAToken) driver.OwnedSAProof
}

type childProofPair struct {
	reader  childProofReader
	in, out driver.OwnedSAToken
}

// Only this small immutable-token view is shared with readers. They never
// acquire rekeyMu/childMu or read the mutable SA/retirement/key structures.
type childProofState struct {
	mu                sync.Mutex
	epoch             uint64
	changing          int
	owner             context.Context
	current, previous *childProofPair
	previousPhase     string
}

type childProofChange struct {
	epoch             uint64
	current, previous *childProofPair
	previousPhase     string
	ok                bool
}

func (s *Session) beginChildProofChange() *childProofChange {
	p := &s.saProof
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	p.changing++
	return &childProofChange{epoch: p.epoch, current: p.current, previous: p.previous, previousPhase: p.previousPhase}
}

func (s *Session) finishChildProofChange(change *childProofChange) {
	p := &s.saProof
	p.mu.Lock()
	defer p.mu.Unlock()
	p.changing--
	if !change.ok || p.epoch != change.epoch || p.changing != 0 {
		p.current = nil
		return
	}
	p.current, p.previous, p.previousPhase = change.current, change.previous, change.previousPhase
}

func (s *Session) clearChildSAProof() {
	p := &s.saProof
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	p.owner, p.current, p.previous = nil, nil, nil
	p.previousPhase = ""
}

func captureChildProofPair(manager *driver.XFRMManager, out, in driver.XFRMSAConfig) *childProofPair {
	return &childProofPair{reader: manager,
		in: manager.CaptureOwnedSA(in.SPI, in.Dst, in.Proto), out: manager.CaptureOwnedSA(out.SPI, out.Dst, out.Proto)}
}

func (s *Session) captureRekeyProof(ops childRekeyXFRMOps, next childSARekey) *childProofPair {
	manager, ok := ops.(*driver.XFRMManager)
	if !ok {
		return nil
	}
	return captureChildProofPair(manager,
		driver.XFRMSAConfig{SPI: next.out.SPI, Dst: s.xfrmRemoteIP, Proto: netlink.XFRM_PROTO_ESP},
		driver.XFRMSAConfig{SPI: next.in.SPI, Dst: s.xfrmLocalIP, Proto: netlink.XFRM_PROTO_ESP})
}

func (pair *childProofPair) read(ctx context.Context) *ChildSAPairProof {
	return &ChildSAPairProof{Inbound: pair.reader.ReadOwnedSAProof(ctx, pair.in), Outbound: pair.reader.ReadOwnedSAProof(ctx, pair.out)}
}

// ReadChildSAProof is explicit and bounded to four exact owned GETs / one
// second. Socket cancellation latency is bounded by the driver's per-read
// timeout, not instant syscall interruption. No lifecycle mutex spans I/O.
func (s *Session) ReadChildSAProof(ctx context.Context) ChildSAProof {
	p := &s.saProof
	if !p.mu.TryLock() {
		return ChildSAProof{State: "unavailable"}
	}
	epoch, owner, current, previous, phase := p.epoch, p.owner, p.current, p.previous, p.previousPhase
	ready := p.changing == 0 && owner != nil && owner.Err() == nil && current != nil
	p.mu.Unlock()
	if !ready {
		return ChildSAProof{State: "unavailable"}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	stop := context.AfterFunc(owner, cancel)
	defer stop()
	if ctx.Err() != nil {
		return ChildSAProof{State: "unknown"}
	}
	result := ChildSAProof{State: "unverified", Current: current.read(ctx), Previous: &PreviousChildSAProof{State: "not-observed"}}
	if result.Current.Inbound.State == "verified" && result.Current.Outbound.State == "verified" {
		result.State = "verified"
	}
	if previous != nil && ctx.Err() == nil {
		old := previous.read(ctx)
		state := "unknown"
		switch {
		case old.Inbound.State == "absent" && old.Outbound.State == "absent":
			state = "absent"
		case phase == "overlap" && old.Inbound.State == "verified" && old.Outbound.State == "verified":
			state = "overlap"
		case saPresent(old.Inbound.State) || saPresent(old.Outbound.State):
			state = "present-or-reused"
		}
		result.Previous = &PreviousChildSAProof{State: state, Phase: phase, Pair: old}
	}
	if ctx.Err() != nil || owner.Err() != nil {
		return ChildSAProof{State: "unknown"}
	}
	if !p.mu.TryLock() {
		return ChildSAProof{State: "stale"}
	}
	stable := p.epoch == epoch && p.changing == 0 && p.owner == owner && p.current == current
	p.mu.Unlock()
	if !stable {
		return ChildSAProof{State: "stale"}
	}
	return result
}

func saPresent(state string) bool {
	return state == "verified" || state == "mismatch" || state == "present-or-reused"
}
