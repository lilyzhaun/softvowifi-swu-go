package ikev2

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestParseCPConfigPrivatePCSCFDoesNotGuessUnknownShapes(t *testing.T) {
	standard := net.ParseIP("2001:db8::9").To16()
	legacy := net.ParseIP("2001:db8::99").To16()
	for _, size := range []int{0, 1, 15, 16, 17, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			value := make([]byte, size)
			copy(value, legacy)
			cp := &EncryptedPayloadCP{CFGType: CFG_REPLY, Attributes: []*CPAttribute{
				{Type: P_CSCF_IP6_ADDRESS, Value: bytes.Clone(standard)},
				{Type: ASSIGNED_PCSCF_IP6_ADDRESS, Value: value},
			}}
			cfg := ParseCPConfig(cp)
			want := 1
			if size == 16 {
				want++
			}
			if len(cfg.IPv6PCSCF) != want || !cfg.IPv6PCSCF[0].Equal(standard) {
				t.Fatal("private CP format was guessed or valid standard P-CSCF was lost")
			}
			if size == 16 && !cfg.IPv6PCSCF[1].Equal(legacy) {
				t.Fatal("supported legacy 16-byte private P-CSCF was lost")
			}
		})
	}
}
