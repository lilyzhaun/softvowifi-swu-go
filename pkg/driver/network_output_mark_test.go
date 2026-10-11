package driver

import (
	"reflect"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestNetworkOutputMarkDoesNotChangeStateIdentity(t *testing.T) {
	for _, mark := range []uint32{0, 0x12345678} {
		cfg := XFRMSAConfig{SPI: 100, Mode: netlink.XFRM_MODE_TUNNEL, SADir: netlink.XFRM_SA_DIR_OUT}
		field := reflect.ValueOf(&cfg).Elem().FieldByName("OutputMark")
		if !field.IsValid() {
			t.Fatal("XFRM has no selected-platform output routing mark")
		}
		field.SetUint(uint64(mark))
		state := NewXFRMManager().buildXfrmState(cfg)
		if state.Mark != nil {
			t.Fatal("output routing mark became an inbound/ownership lookup selector")
		}
		if mark == 0 {
			if state.OutputMark != nil {
				t.Fatal("unbound legacy state gained an output mark")
			}
		} else if state.OutputMark == nil || state.OutputMark.Value != mark || state.OutputMark.Mask != ^uint32(0) {
			t.Fatal("selected platform mark was not preserved exactly")
		}
	}
}
