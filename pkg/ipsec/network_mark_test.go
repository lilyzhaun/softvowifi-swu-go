package ipsec

import (
	"errors"
	"syscall"
	"testing"
)

func TestNetworkOutputMarkReadsTheActuallyBoundSocket(t *testing.T) {
	s, err := NewSocketManagerWithControl(t.Context(), "127.0.0.1:0", "127.0.0.1:500", "", func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 0x12345678)
		}); err != nil {
			return err
		}
		return socketErr
	})
	if errors.Is(err, syscall.EPERM) {
		t.Skip("SO_MARK requires a privileged isolated fixture")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer s.Conn.Close()
	mark, err := s.OutputMark()
	if err != nil || mark != 0x12345678 {
		t.Fatal("output mark was guessed instead of read from bound socket")
	}
}
