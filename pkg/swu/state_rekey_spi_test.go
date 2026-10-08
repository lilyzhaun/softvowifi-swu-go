package swu

import "testing"

func TestChildRekeyNotifyUsesInboundSPI(t *testing.T) {
	for _, pair := range [][2]uint32{{0x01020304, 0xa1b2c3d4}, {0xa1b2c3d4, 0x01020304}} {
		sess, _ := childRekeySession(t)
		sess.ChildSAOut.SPI, sess.ChildSAIn.SPI = pair[0], pair[1]
		clear(sess.ChildSAsIn)
		sess.ChildSAsIn[pair[1]] = sess.ChildSAIn
		if err := exerciseChildRekey(t, sess, sess.RekeyChildSA); err != nil {
			t.Fatalf("rekey with distinct directional SPIs: %v", err)
		}
	}
}

func TestChildRekeyRequiresBothSAs(t *testing.T) {
	for _, missing := range []string{"inbound", "outbound"} {
		t.Run(missing, func(t *testing.T) {
			sess, pipe := childRekeySession(t)
			if missing == "inbound" {
				sess.ChildSAIn = nil
			} else {
				sess.ChildSAOut = nil
			}
			if err := sess.RekeyChildSA(); err == nil {
				t.Fatal("rekey accepted an incomplete Child SA pair")
			}
			if len(pipe.sent) != 0 {
				t.Fatal("rekey sent a request without a complete Child SA pair")
			}
		})
	}
}
