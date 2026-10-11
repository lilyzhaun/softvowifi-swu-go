package swu

import "testing"

func TestNetworkChildRekeyPreservesBoundOutputMarkOnlyOutbound(t *testing.T) {
	s, next := rekeyXFRMFixture()
	s.xfrmOutputMark = 0x12345678
	kernel := newRekeyKernel()
	if err := s.rekeyXFRM(kernel, next, [2]uint32{101, 102}); err != nil {
		t.Fatal(err)
	}
	if kernel.adds[0].OutputMark != 0x12345678 || kernel.adds[1].OutputMark != 0 {
		t.Fatal("Child rekey changed the platform output route or inbound state")
	}
}
