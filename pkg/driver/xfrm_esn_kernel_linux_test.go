//go:build linux

package driver

import (
	"context"
	"net"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/iniwex5/netlink"
)

func TestESNKernelManagerReadbackAndLifetimeUpdate(t *testing.T) {
	if os.Getenv("VOWIFI_ESN_KERNEL_TEST") != "1" {
		t.Skip("requires an explicitly isolated network namespace")
	}
	parent := os.Getenv("VOWIFI_ESN_PARENT_NS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || parent == "" || parent == current {
		t.Fatal("ESN kernel test must not run in the parent network namespace")
	}
	ip := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "ip", args...).Run()
	}
	for _, list := range []func() (int, error){
		func() (int, error) { states, err := netlink.XfrmStateList(netlink.FAMILY_ALL); return len(states), err },
		func() (int, error) {
			policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
			return len(policies), err
		},
	} {
		if n, err := list(); err != nil || n != 0 {
			t.Fatal("isolated ESN namespace must start with empty SAD/SPD")
		}
	}
	owner := NewXFRMManager()
	cfg := XFRMSAConfig{Src: net.ParseIP("192.0.2.1"), Dst: net.ParseIP("192.0.2.2"),
		SPI: 0x10203040, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
		ESN: true, ReplayWindow: 64, IsAEAD: true, AeadAlgoName: "rfc4106(gcm(aes))",
		AeadKey: []byte("1234567890123456salt"), AeadICVLen: 128}
	// Direction zero deliberately exercises the established legacy kernel path,
	// not Linux 7's explicit SADir OUT/window compatibility boundary.
	policy := ownershipSP(0)
	policy.TmplSPI = int(cfg.SPI)
	linkAdded, saAdded, policyAdded := false, false, false
	t.Cleanup(func() {
		if policyAdded {
			if err := owner.DelSP(policy); err != nil {
				t.Errorf("exact ESN policy cleanup failed: %v", err)
			}
		}
		if saAdded {
			if err := owner.DelSA(cfg.SPI, cfg.Src, cfg.Dst, cfg.Proto); err != nil {
				t.Errorf("exact ESN SA cleanup failed: %v", err)
			}
		}
		if linkAdded {
			if err := ip("link", "del", "esn-test0"); err != nil {
				t.Errorf("exact synthetic link cleanup failed: %v", err)
			}
		}
		if states, err := netlink.XfrmStateList(netlink.FAMILY_ALL); err != nil || len(states) != 0 {
			t.Error("ESN SAD is not empty after cleanup")
		}
		if policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL); err != nil || len(policies) != 0 {
			t.Error("ESN SPD is not empty after cleanup")
		}
	})
	if err := ip("link", "add", "esn-test0", "type", "dummy"); err != nil {
		t.Fatal("synthetic ESN link setup failed")
	}
	linkAdded = true
	for _, args := range [][]string{
		{"addr", "add", "192.0.2.1/24", "dev", "esn-test0"},
		{"addr", "add", "198.51.100.1/32", "dev", "esn-test0"},
		{"link", "set", "esn-test0", "up"},
		{"route", "add", "203.0.113.1/32", "dev", "esn-test0", "src", "198.51.100.1"},
	} {
		if err := ip(args...); err != nil {
			t.Fatal("synthetic ESN route setup failed")
		}
	}
	mustXFRM(t, owner.AddSA(cfg))
	saAdded = true
	mustXFRM(t, owner.AddSP(policy))
	policyAdded = true
	query := &netlink.XfrmState{Dst: cfg.Dst, Spi: int(cfg.SPI), Proto: cfg.Proto}
	get := func() *netlink.XfrmState {
		t.Helper()
		state, err := netlink.XfrmStateGet(query)
		if err != nil || !state.ESN || state.ReplayWindow != 64 || state.ReplayESN == nil {
			t.Fatal("real manager-owned ESN state readback failed")
		}
		return state
	}
	get()
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.51.100.1")}, &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		if _, err := conn.Write([]byte("synthetic-esn-probe")); err != nil {
			t.Fatal(err)
		}
	}
	before := get()
	if before.ReplayESN.OSeq != 3 || before.ReplayESN.OSeqHi != 0 {
		t.Fatal("synthetic traffic did not use the real ESN ESP output path")
	}
	cfg.TimeLimitSoft, cfg.TimeLimitHard = 60, 120
	mustXFRM(t, owner.UpdateSA(cfg))
	after := get()
	if !reflect.DeepEqual(before.ReplayESN, after.ReplayESN) || after.Limits.TimeSoft != 60 || after.Limits.TimeHard != 120 {
		t.Fatal("manager lifetime update changed replay state or lost limits")
	}
	if _, err := conn.Write([]byte("synthetic-esn-probe")); err != nil {
		t.Fatal(err)
	}
	if state := get(); state.ReplayESN.OSeq != 4 || state.ReplayESN.OSeqHi != 0 {
		t.Fatal("ESN output did not continue from the pre-update sequence")
	}
}
