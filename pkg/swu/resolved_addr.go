package swu

import (
	"errors"
	"fmt"
)

var ErrDiagnosticRedirect = errors.New("diagnostic endpoint is fixed: redirect refused")

func (c *Config) acceptRedirect(addr string) error {
	if c.DiagnosticRemoteIP.IsValid() {
		return ErrDiagnosticRedirect
	}
	c.EpDGAddr = addr
	return nil
}

func (c *Config) resolvedRemoteAddr(port uint16) string {
	host := c.EpDGAddr
	if c.DiagnosticRemoteIP.IsValid() {
		host = c.DiagnosticRemoteIP.String()
	}
	return fmt.Sprintf("%s:%d", host, port)
}
