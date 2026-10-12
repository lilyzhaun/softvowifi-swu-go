package swu

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/iniwex5/netlink"
)

func TestPeerChildRekeyKernelRetiresOnlyThePredecessor(t *testing.T) {
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
	s, pipe, p := peerChildFixture(t, peerChildSuites[2])
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
	foreign.SPI = 0x77777777
	foreign.Ifid = 38
	if err := canary.AddSA(foreign); err != nil {
		t.Fatal(err)
	}
	for _, sa := range []driver.XFRMSAConfig{out, in} {
		if err := mgr.AddSA(sa); err != nil {
			t.Fatal(err)
		}
	}
	for _, sp := range policies {
		if err := mgr.AddSP(sp); err != nil {
			t.Fatal(err)
		}
	}
	s.xfrmMgr = mgr
	s.dispatchReceivedIKE(encodePeerPacket(t, s, p, ikev2.CREATE_CHILD_SA, 0, false), nil)
	<-pipe.sent
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 5 {
		t.Fatalf("overlap state count=%d err=%v", len(states), err)
	}
	installed, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range installed {
		if sp.Dir == netlink.XFRM_DIR_IN && (sp.Ifid != 37 || len(sp.Tmpls) != 1 || sp.Tmpls[0].Proto != netlink.XFRM_PROTO_ESP || sp.Tmpls[0].Spi != 0) {
			t.Fatal("overlap lost mandatory ESP/owner scope")
		}
	}
	d := &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, old.out.SPI)}
	s.dispatchReceivedIKE(encodeInformational(t, s, d), nil)
	<-pipe.sent
	states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 3 {
		t.Fatalf("retired state count=%d err=%v", len(states), err)
	}
	if err := mgr.CleanupOwned(); err != nil {
		t.Fatal(err)
	}
	states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 1 || uint32(states[0].Spi) != foreign.SPI {
		t.Fatalf("own cleanup changed canary or leaked SA: count=%d err=%v", len(states), err)
	}
	if err := canary.CleanupOwned(); err != nil {
		t.Fatal(err)
	}
	t.Log("old/new kernel states and mandatory overlap policy verified; foreign canary preserved, owned namespace cleaned")
}
