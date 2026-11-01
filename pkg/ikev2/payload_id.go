package ikev2

import (
	"bytes"
	"errors"
)

// 身份标识载荷 (RFC 7296 3.5 节)
type EncryptedPayloadID struct {
	IDType       uint8
	IDData       []byte
	IsInitiator  bool // 辅助字段，用于确定 Type() 返回值
	receivedBody []byte
}

const (
	ID_IPV4_ADDR   = 1
	ID_FQDN        = 2
	ID_RFC822_ADDR = 3
	ID_IPV6_ADDR   = 5
	ID_DER_ASN1_DN = 9
	ID_DER_ASN1_GN = 10
	ID_KEY_ID      = 11
)

func (p *EncryptedPayloadID) Type() PayloadType {
	if p.IsInitiator {
		return IDi
	}
	return IDr
}

func (p *EncryptedPayloadID) Encode() ([]byte, error) {
	// 头部: 1 字节 ID 类型 + 3 字节保留 + 数据
	buf := make([]byte, 4+len(p.IDData))
	buf[0] = p.IDType
	// buf[1:4] 保留 = 0
	copy(buf[4:], p.IDData)
	return buf, nil
}

// AuthenticationBody returns an owned copy of the received ID payload body,
// including RESERVED bytes, for RFC 7296 section 2.15 authentication. Mutating
// the decoded fields does not rewrite that transcript. Locally constructed IDs
// use their outgoing encoding; Encode always sends zero RESERVED bytes.
func (p *EncryptedPayloadID) AuthenticationBody() ([]byte, error) {
	if p.receivedBody != nil {
		return bytes.Clone(p.receivedBody), nil
	}
	return p.Encode()
}

func DecodePayloadID(data []byte, isInitiator bool) (*EncryptedPayloadID, error) {
	if len(data) < 4 {
		return nil, errors.New("ID 载荷太短")
	}
	return &EncryptedPayloadID{
		IDType:       data[0],
		IDData:       bytes.Clone(data[4:]),
		IsInitiator:  isInitiator,
		receivedBody: bytes.Clone(data),
	}, nil
}
