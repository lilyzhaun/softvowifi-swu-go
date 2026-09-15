package driver

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type TUNDevice struct {
	fd   int
	Name string
}

func NewTUNDevice(name string) (*TUNDevice, error) {
	if name != "" {
		nt := NewNetTools()
		nt.DeleteLink(name)
	}

	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("打开 /dev/net/tun: %w", err)
	}

	var ifr [40]byte
	copy(ifr[:16], name)
	ifr[16] = 0x01 // IFF_TUN
	ifr[17] = 0x10 // IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	devName := string(ifr[:])
	for i, b := range ifr[:16] {
		if b == 0 {
			devName = string(ifr[:i])
			break
		}
	}

	return &TUNDevice{fd: fd, Name: devName}, nil
}

func (t *TUNDevice) Read(p []byte) (n int, err error) {
	fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
	for {
		pn, perr := unix.Poll(fds, 5000)
		if pn > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return syscall.Read(t.fd, p)
		}
		if perr != nil && perr != syscall.EINTR {
			return 0, perr
		}
	}
}

func (t *TUNDevice) Write(p []byte) (n int, err error) {
	return syscall.Write(t.fd, p)
}

func (t *TUNDevice) Close() error {
	return syscall.Close(t.fd)
}

func (t *TUNDevice) DeviceName() string {
	return t.Name
}
