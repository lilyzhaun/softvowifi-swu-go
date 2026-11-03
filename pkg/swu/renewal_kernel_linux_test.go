package swu

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/iniwex5/netlink"
)

func TestRenewalPolicyInitialAndMobikeKernelLifetimes(t *testing.T) {
	if os.Getenv("ISSUE33_KERNEL_TEST") != "1" {
		t.Skip("requires explicit isolated child namespace")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if parent := os.Getenv("ISSUE33_PARENT_NETNS"); parent == "" || parent == ns {
		t.Fatal("refusing unisolated kernel operations")
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	s, _ := renewalCryptoSession(t)
	defer s.cancel()
	setRenewalInput(t, s.cfg, renewalInput())
	s.cfg.TUNName, s.cfg.XFRMIfID = "renewal0", 0x528
	// The scheduler fixture has one-byte placeholder Child keys. Derive a
	// complete synthetic pair before exercising the real kernel consumer.
	pair, err := s.deriveChildRekey(s.childEncrID, s.childIntegID, s.childEncrKeyLenBits,
		make([]byte, 32), make([]byte, 32), 202, 201, true)
	if err != nil {
		t.Fatal(err)
	}
	s.ChildSAIn, s.ChildSAOut = pair.in, pair.out
	for _, sa := range []*ipsec.SecurityAssociation{s.ChildSAIn, s.ChildSAOut} {
		if len(sa.EncryptionKey) != 16 || len(sa.IntegrityKey) != 32 {
			t.Fatal("kernel fixture does not contain complete CBC128/SHA256 keys")
		}
	}
	// A real bound outer socket is required by production initial XFRM setup.
	socket, err := ipsec.NewSocketManagerWithObserver(s.ctx, "127.0.0.1:0", "127.0.0.2:4500", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.socket = socket
	socket.Start()
	defer socket.Stop()
	defer func() {
		if err := s.cleanupNetworkConfig(); err != nil {
			t.Error(err)
		}
	}()
	s.renewChildHardExpiry(time.Now())
	due := s.childHardExpiry.deadline()
	if err := s.setupXFRMDataPlane(); err != nil {
		t.Fatal(err)
	}
	if s.ReadChildSAProof(context.Background()).State != "unavailable" {
		t.Fatal("installation before authenticated publication yielded proof")
	}
	s.publishNegotiatedSecurity()
	checkProof := func() {
		t.Helper()
		proof := s.ReadChildSAProof(context.Background())
		if proof.State != "verified" || proof.Current == nil || proof.Previous.State != "not-observed" {
			t.Fatal("production initial/MOBIKE proof did not read the actual pair")
		}
		for _, sa := range []driver.OwnedSAProof{proof.Current.Inbound, proof.Current.Outbound} {
			if sa.State != "verified" || sa.Limits == nil || sa.Limits.SoftSeconds != 120 || sa.Limits.HardSeconds != 180 {
				t.Fatal("proof differs from captured kernel lifetimes")
			}
		}
	}
	checkProof()
	check := func() map[int]uint64 {
		t.Helper()
		states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
		if err != nil || len(states) != 2 {
			t.Fatalf("kernel pair count=%d err=%v", len(states), err)
		}
		ages := map[int]uint64{}
		for _, state := range states {
			if state.Limits.TimeSoft != 120 || state.Limits.TimeHard != 180 {
				t.Fatal("kernel lifetime differs from captured policy")
			}
			ages[state.Spi] = state.Statistics.AddTime
		}
		return ages
	}
	before := check()
	// Cross a kernel seconds-clock boundary so an age reset is observable.
	time.Sleep(1100 * time.Millisecond)
	s.cfg.RenewalPolicy.Child.SoftLifetime, s.cfg.RenewalPolicy.Child.HardLifetime = time.Hour, 2*time.Hour
	if err := s.updateXFRMState(net.IPv4(127, 0, 0, 1).String(), net.IPv4(127, 0, 0, 2).String()); err != nil {
		t.Fatal(err)
	}
	for spi, age := range check() {
		if age != before[spi] {
			t.Fatal("address update reset an existing kernel SA's age")
		}
	}
	if !s.childHardExpiry.deadline().Equal(due) {
		t.Fatal("MOBIKE extended the Session's original hard deadline")
	}
	checkProof()
	if err := s.cleanupNetworkConfig(); err != nil {
		t.Fatal(err)
	}
	if s.ReadChildSAProof(context.Background()).State != "unavailable" {
		t.Fatal("cleanup left a live proof owner")
	}
}
