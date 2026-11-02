package driver

import (
	"context"
	"net"
	"time"

	"github.com/iniwex5/netlink"
	"golang.org/x/sys/unix"
)

// OwnedSAToken is a read-only capture of a confirmed installation. It grants
// no mutation rights and deliberately has no endpoint/SPI/key serialization.
type OwnedSAToken struct{ capture *ownedSACapture }

type ownedSACapture struct {
	manager    *XFRMManager
	key        stateKey
	generation uint64
	snapshot   stateSnapshot
}

func (OwnedSAToken) String() string               { return "owned-sa-token" }
func (OwnedSAToken) GoString() string             { return "owned-sa-token" }
func (OwnedSAToken) MarshalJSON() ([]byte, error) { return []byte("null"), nil }

type SALifetimeLimits struct {
	SoftSeconds uint64 `json:"softSeconds"`
	HardSeconds uint64 `json:"hardSeconds"`
}

// OwnedSAProof is a point-in-time read, not a remaining lifetime, proof of
// traffic, or an assurance that the kernel cannot change after the read.
type OwnedSAProof struct {
	State  string            `json:"state"`
	Limits *SALifetimeLimits `json:"limits,omitempty"`
}

// CaptureOwnedSA does not query the kernel. Unknown/unconfirmed tuples yield
// an empty token; callers cannot acquire a token for another manager's SA.
func (x *XFRMManager) CaptureOwnedSA(spi uint32, dst net.IP, proto netlink.Proto) OwnedSAToken {
	if !x.mu.TryLock() {
		return OwnedSAToken{}
	}
	defer x.mu.Unlock()
	key := stateIdentity(&netlink.XfrmState{Dst: dst, Spi: int(spi), Proto: proto})
	record := x.states[key]
	if record == nil || record.confirmErr != nil {
		return OwnedSAToken{}
	}
	return OwnedSAToken{&ownedSACapture{x, key, record.generation, record.snapshot}}
}

// ReadOwnedSAProof performs one exact GET without holding the lifecycle lock.
// Only a real ENOENT/ESRCH means absent, including after a successful DELETE.
func (x *XFRMManager) ReadOwnedSAProof(ctx context.Context, token OwnedSAToken) OwnedSAProof {
	unknown := OwnedSAProof{State: "unknown"}
	if ctx.Err() != nil {
		return unknown
	}
	capture := token.capture
	if capture == nil || capture.manager != x || !x.mu.TryLock() {
		return OwnedSAProof{State: "unavailable"}
	}
	epoch, read := x.generation, x.ops.stateRead
	record := x.states[capture.key]
	owned := record != nil && record.confirmErr == nil && record.generation == capture.generation && record.snapshot == capture.snapshot
	x.mu.Unlock()
	if read == nil {
		return unknown
	}
	actual, err := read(ctx, capture.key.query())
	if actual != nil {
		defer func() {
			for _, algo := range []*netlink.XfrmStateAlgo{actual.Auth, actual.Crypt, actual.Aead} {
				if algo != nil {
					clear(algo.Key)
					algo.Key = nil
				}
			}
		}()
	}
	if ctx.Err() != nil {
		return unknown
	}
	if !x.mu.TryLock() {
		return OwnedSAProof{State: "stale"}
	}
	stable := x.generation == epoch
	x.mu.Unlock()
	if !stable {
		return OwnedSAProof{State: "stale"}
	}
	if resourceAbsent(err) {
		return OwnedSAProof{State: "absent"}
	}
	if err != nil || actual == nil {
		return unknown
	}
	if !owned {
		return OwnedSAProof{State: "present-or-reused"}
	}
	if snapshotState(actual) != capture.snapshot {
		return OwnedSAProof{State: "mismatch"}
	}
	return OwnedSAProof{State: "verified", Limits: &SALifetimeLimits{actual.Limits.TimeSoft, actual.Limits.TimeHard}}
}

func readXFRMStateBounded(ctx context.Context, query *netlink.XfrmState) (*netlink.XfrmState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, err := netlink.NewHandle(unix.NETLINK_XFRM)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	timeout := 250 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := handle.SetSocketTimeout(timeout); err != nil {
		return nil, err
	}
	return handle.XfrmStateGet(query)
}
