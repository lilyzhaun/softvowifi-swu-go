package swu

import "net"

// NAT detection hashes contain exactly 4 or 16 address octets (RFC7296 2.23).
func natIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}
