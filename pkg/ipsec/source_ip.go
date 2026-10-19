package ipsec

import (
	"errors"
	"net"
)

func selectSourceIP(local, remote net.IP, source func(net.IP) (net.IP, error)) (net.IP, error) {
	if source != nil {
		var err error
		local, err = source(remote)
		if err != nil {
			return nil, err
		}
		if local == nil || local.IsUnspecified() {
			return nil, errors.New("selected network returned no source address")
		}
	}
	if local != nil && !local.IsUnspecified() && (remote == nil || (local.To4() != nil) != (remote.To4() != nil)) {
		return nil, errors.New("no source address matching destination family")
	}
	return local, nil
}
