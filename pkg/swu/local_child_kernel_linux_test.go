package swu

import (
	"os"
	"testing"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/iniwex5/netlink"
)

func TestLocalChildRekeyKernelCommitsSelectedSuiteAfterGCM(t *testing.T) {
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
	s, _ := childRekeySession(t)
	s.childEncrID, s.childIntegID, s.childEncrKeyLenBits, s.childESN = uint16(ikev2.ENCR_AES_GCM_16), 0, 256, false
	old, err := s.deriveChildRekey(s.childEncrID, 0, 256, make([]byte, 32), make([]byte, 32), 102, 101, true)
	if err != nil {
		t.Fatal(err)
	}
	s.ChildSAIn, s.ChildSAOut = old.in, old.out
	s.ChildSAsIn[102] = old.in
	mgr := driver.NewXFRMManager()
	defer mgr.CleanupOwned()
	out, in, policies, err := s.childRekeyXFRMConfigs(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, sa := range []driver.XFRMSAConfig{out, in} {
		if err := mgr.AddSA(sa); err != nil {
			t.Fatal(err)
		}
	}
	for _, policy := range policies {
		if err := mgr.AddSP(policy); err != nil {
			t.Fatal(err)
		}
	}
	s.xfrmMgr = mgr
	if err := exerciseChildRekey(t, s, s.RekeyChildSA); err != nil {
		t.Fatal(err)
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 2 {
		t.Fatalf("state count=%d err=%v", len(states), err)
	}
	for _, sa := range states {
		if sa.Aead != nil || sa.Crypt == nil || sa.Crypt.Name != "cbc(aes)" || len(sa.Crypt.Key) != 16 || sa.Auth == nil || sa.Auth.Name != "hmac(sha256)" || len(sa.Auth.Key) != 32 || sa.Auth.TruncateLen != 128 {
			t.Fatal("actual kernel retained old GCM suite instead of selected CBC128/SHA256")
		}
	}
	if err := mgr.CleanupOwned(); err != nil {
		t.Fatal(err)
	}
	states, err = netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 0 {
		t.Fatal("owned rekey states not removed")
	}
	t.Log("real kernel changed GCM256 to selected CBC128/SHA256 and removed owned states")
}
