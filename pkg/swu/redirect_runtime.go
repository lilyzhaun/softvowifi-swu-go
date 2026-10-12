package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// RFC 5685 section 9.2: type, length, identity; no nonce in a protected
// gateway-initiated redirect. Keep the unauthenticated SA_INIT path separate.
func parseRuntimeRedirect(n *ikev2.EncryptedPayloadNotify) (string, error) {
	data := n.NotifyData
	if n.ProtocolID != 0 || len(n.SPI) != 0 || len(data) < 2 || data[1] == 0 || int(data[1]) != len(data)-2 {
		return "", errors.New("invalid protected redirect identity framing")
	}
	return ParseRedirectData(append([]byte{data[0]}, data[2:]...))
}
