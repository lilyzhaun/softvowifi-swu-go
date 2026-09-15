package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

type akaWirePeer struct {
	conn                           *net.UDPConn
	address                        *net.UDPAddr
	header                         ikev2.IKEHeader
	keys                           []byte
	initRequest, initResponse      []byte
	initiatorNonce, responderNonce []byte
}

func newAKAWirePeer(t *testing.T) *akaWirePeer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return &akaWirePeer{conn: conn}
}

func (peer *akaWirePeer) receive(t *testing.T) []byte {
	t.Helper()
	buffer := make([]byte, 4096)
	count, address, err := peer.conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if peer.address != nil && peer.address.String() != address.String() {
		t.Fatal("client UDP endpoint changed")
	}
	peer.address = address
	return bytes.Clone(buffer[:count])
}

func (peer *akaWirePeer) send(t *testing.T, raw []byte) {
	t.Helper()
	count, err := peer.conn.WriteToUDP(raw, peer.address)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(raw) {
		t.Fatal("partial peer datagram")
	}
}

func (peer *akaWirePeer) negotiate(t *testing.T) {
	t.Helper()
	raw := peer.receive(t)
	sa, ke, _ := decodeInitSA(t, raw)
	request, err := ikev2.DecodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if request.Header.MessageID != 0 || request.Header.SPIr != 0 || request.Header.SPIi == 0 || request.Header.Flags != 8 {
		t.Fatal("invalid initial IKE header")
	}
	if len(sa.Proposals) != 4 {
		t.Fatal("missing fourth default proposal")
	}
	chosen, err := (&ikev2.EncryptedPayloadSA{Proposals: sa.Proposals[3:4]}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := referenceHex(t, "0000002c040100040300000c0100000c800e0100030000080300000c0300000802000005000000080400000e")
	if !bytes.Equal(chosen, want) {
		t.Fatal("fourth suite differs from AES256/SHA256/PRF256/DH14")
	}
	var ni []byte
	for _, payload := range request.Payloads {
		if nonce, ok := payload.(*ikev2.EncryptedPayloadNonce); ok {
			ni = bytes.Clone(nonce.NonceData)
		}
	}
	if len(ni) < 16 {
		t.Fatal("missing initiator nonce")
	}
	dh, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatal(err)
	}
	if err := dh.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	secret, err := dh.ComputeSharedSecret(ke.KEData)
	if err != nil {
		t.Fatal(err)
	}
	nr := bytes.Repeat([]byte{9}, 32)
	peer.header = ikev2.IKEHeader{SPIi: request.Header.SPIi, SPIr: 4321, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
	response := &ikev2.IKEPacket{Header: &peer.header, Payloads: []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: sa.Proposals[3:4]},
		&ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: dh.PublicKeyBytes()},
		&ikev2.EncryptedPayloadNonce{NonceData: nr},
	}}
	encoded, err := response.Encode()
	if err != nil {
		t.Fatal(err)
	}
	peer.keys = independentSHA256Keys(secret, append(ni, nr...), &peer.header)
	peer.initRequest, peer.initResponse = bytes.Clone(raw), bytes.Clone(encoded)
	peer.initiatorNonce, peer.responderNonce = bytes.Clone(ni), bytes.Clone(nr)
	peer.send(t, encoded)
}

func (peer *akaWirePeer) protect(t *testing.T, payloads []akaWirePayload) []byte {
	t.Helper()
	var plain []byte
	for index, payload := range payloads {
		next := byte(0)
		if index+1 < len(payloads) {
			next = payloads[index+1].kind
		}
		plain = append(plain, next, 0)
		plain = binary.BigEndian.AppendUint16(plain, uint16(len(payload.body)+4))
		plain = append(plain, payload.body...)
	}
	padding := (16 - (len(plain)+1)%16) % 16
	plain = append(plain, make([]byte, padding)...)
	plain = append(plain, byte(padding))
	iv := bytes.Repeat([]byte{3}, 16)
	block, err := aes.NewCipher(peer.keys[128:160])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	peer.header.MessageID++
	raw := binary.BigEndian.AppendUint64(nil, peer.header.SPIi)
	raw = binary.BigEndian.AppendUint64(raw, peer.header.SPIr)
	raw = append(raw, 46, 0x20, 35, 0x20)
	raw = binary.BigEndian.AppendUint32(raw, peer.header.MessageID)
	raw = binary.BigEndian.AppendUint32(raw, uint32(64+len(plain)))
	raw = append(raw, payloads[0].kind, 0)
	raw = binary.BigEndian.AppendUint16(raw, uint16(36+len(plain)))
	raw = append(raw, iv...)
	raw = append(raw, plain...)
	mac := hmac.New(sha256.New, peer.keys[64:96])
	mac.Write(raw)
	return append(raw, mac.Sum(nil)[:16]...)
}

func (peer *akaWirePeer) decrypt(t *testing.T, raw []byte) []akaWirePayload {
	t.Helper()
	if len(raw) < 80 || (len(raw)-64)%16 != 0 || int(binary.BigEndian.Uint32(raw[24:28])) != len(raw) {
		t.Fatal("invalid IKE encrypted datagram length")
	}
	if binary.BigEndian.Uint64(raw[:8]) != peer.header.SPIi || binary.BigEndian.Uint64(raw[8:16]) != peer.header.SPIr ||
		!bytes.Equal(raw[16:20], []byte{46, 0x20, 35, 8}) || binary.BigEndian.Uint32(raw[20:24]) != peer.header.MessageID+1 {
		t.Fatal("AUTH request SPI, version, exchange, flags or message ID mismatch")
	}
	if raw[29] != 0 || int(binary.BigEndian.Uint16(raw[30:32])) != len(raw)-28 {
		t.Fatal("invalid SK generic header")
	}
	mac := hmac.New(sha256.New, peer.keys[32:64])
	mac.Write(raw[:len(raw)-16])
	if !hmac.Equal(mac.Sum(nil)[:16], raw[len(raw)-16:]) {
		t.Fatal("independent peer rejected outer ICV")
	}
	block, err := aes.NewCipher(peer.keys[96:128])
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(raw)-64)
	cipher.NewCBCDecrypter(block, raw[32:48]).CryptBlocks(plain, raw[48:len(raw)-16])
	padding := int(plain[len(plain)-1])
	if padding >= len(plain) {
		t.Fatal("invalid IKE padding length")
	}
	return parseAKAWirePayloads(t, raw[28], plain[:len(plain)-padding-1])
}
