package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/iniwex5/netlink"
)

func TestChildPFSKernelLocalAndPeerInstallationRetirement(t *testing.T) {
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
	for _, direction := range []string{"local", "peer"} {
		t.Run(direction, func(t *testing.T) {
			s, pipe := childRekeySession(t)
			var request []ikev2.Payload
			if direction == "peer" {
				s, pipe, request = peerChildPFSFixture(t, peerChildSuites[2])
			}
			s.cfg.ChildPFSGroup = 14
			// This PFS test uses the supported direction-aware driver default
			// (outbound0, inbound32). The mock local fixture's positive128 is
			// an independent replay-policy input, rejected for explicit OUT by
			// Linux7 before any PFS packet; it is not changed in production.
			s.cfg.ReplayWindow = 0
			s.xfrmIfID = 37
			old, err := s.deriveChildRekey(s.childEncrID, s.childIntegID, s.childEncrKeyLenBits, make([]byte, 32), make([]byte, 32), s.ChildSAIn.SPI, s.ChildSAOut.SPI, true)
			if err != nil {
				t.Fatal(err)
			}
			s.ChildSAIn, s.ChildSAOut = old.in, old.out
			s.ChildSAsIn[old.in.SPI] = old.in
			mgr, canary := driver.NewXFRMManager(), driver.NewXFRMManager()
			defer mgr.CleanupOwned()
			defer canary.CleanupOwned()
			out, in, policies, err := s.childRekeyXFRMConfigs(old)
			if err != nil {
				t.Fatal(err)
			}
			foreign := out
			foreign.SPI, foreign.Ifid = 0x77777777, 38
			if err := canary.AddSA(foreign); err != nil {
				t.Fatal(err)
			}
			for _, sa := range []driver.XFRMSAConfig{out, in} {
				if err := mgr.AddSA(sa); err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range policies {
				if err := mgr.AddSP(p); err != nil {
					t.Fatal(err)
				}
			}
			s.xfrmMgr = mgr
			s.saProof.current = captureChildProofPair(mgr, out, in)
			s.publishNegotiatedSecurity()
			assertChildPFSFact(t, s, 0)
			if direction == "local" {
				if _, _, _, err := exerciseChildPFS(t, s, s.RekeyChildSA, nil, nil); err != nil {
					t.Fatal(err)
				}
				<-pipe.sent // the old inbound SPI Delete, checked by wire tests
			} else {
				s.dispatchReceivedIKE(encodePeerPacket(t, s, request, ikev2.CREATE_CHILD_SA, 0, false), nil)
				first := <-pipe.sent
				s.dispatchReceivedIKE(encodePeerPacket(t, s, request, ikev2.CREATE_CHILD_SA, 0, false), nil)
				if !bytes.Equal(<-pipe.sent, first) {
					t.Fatal("kernel-path response replay regenerated the exchange")
				}
				proof := s.ReadChildSAProof(context.Background())
				if proof.State != "verified" || proof.Previous == nil || proof.Previous.State != "overlap" {
					t.Fatal("PFS peer did not verify new kernel pair and old overlap")
				}
				d := &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, old.out.SPI)}
				s.dispatchReceivedIKE(encodePeerPacket(t, s, []ikev2.Payload{d}, ikev2.INFORMATIONAL, 1, false), nil)
				<-pipe.sent
			}
			assertChildPFSFact(t, s, 14)
			proof := s.ReadChildSAProof(context.Background())
			if proof.State != "verified" || proof.Previous == nil || proof.Previous.State != "absent" {
				t.Fatal("new PFS SA or actual old tuple absence not verified")
			}
			states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
			if err != nil || len(states) != 3 {
				t.Fatal("PFS rekey leaked an SA or removed the canary")
			}
			for _, state := range states {
				if uint32(state.Spi) == foreign.SPI {
					continue
				}
				want := s.ChildSAIn
				if uint32(state.Spi) == s.ChildSAOut.SPI {
					want = s.ChildSAOut
				}
				if state.Crypt == nil || !bytes.Equal(state.Crypt.Key, want.EncryptionKey) || state.Auth == nil || !bytes.Equal(state.Auth.Key, want.IntegrityKey) {
					t.Fatal("kernel key bytes differ from actual committed two-way PFS KEYMAT")
				}
			}
			if err := mgr.CleanupOwned(); err != nil {
				t.Fatal(err)
			}
			states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
			if err != nil || len(states) != 1 || uint32(states[0].Spi) != foreign.SPI {
				t.Fatal("owned cleanup leaked state or changed foreign canary")
			}
			if err := canary.CleanupOwned(); err != nil {
				t.Fatal(err)
			}
			states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
			policiesLeft, policyErr := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
			if err != nil || policyErr != nil || len(states) != 0 || len(policiesLeft) != 0 {
				t.Fatal("isolated PFS test left owned states/policies")
			}
			t.Log("actual PFS local/peer keys installed; predecessor absent, canary preserved, namespace cleaned")
		})
	}
}
