package swu

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

func Test_EAPDiagnostics_whenConnectReceivesIdentityThenFailure(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	log, output := diagnosticLogger()
	previousLogger := logger.Get()
	logger.SetLogger(log)
	defer logger.SetLogger(previousLogger)
	provider := &diagnosticSIM{}
	cfg := &Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port), SIM: provider, FastReauthID: "PRIVATE-INITIAL-NAI"}
	sess := NewSession(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	finished := make(chan error, 1)
	go func() { finished <- sess.Connect(ctx) }()
	t.Cleanup(func() { cancel(); sess.Shutdown() })
	buffer := make([]byte, 4096)
	count, address, err := peer.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	offered := bytes.Clone(buffer[:count])
	sa, ke, _ := decodeInitSA(t, offered)
	request, err := ikev2.DecodePacket(offered)
	if err != nil {
		t.Fatal(err)
	}
	var nonces []byte
	for _, payload := range request.Payloads {
		if nonce, ok := payload.(*ikev2.EncryptedPayloadNonce); ok {
			nonces = bytes.Clone(nonce.NonceData)
		}
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
	header := &ikev2.IKEHeader{SPIi: request.Header.SPIi, SPIr: 4321, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
	response := &ikev2.IKEPacket{Header: header, Payloads: []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sa.Proposals[3]}},
		&ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: dh.PublicKeyBytes()},
		&ikev2.EncryptedPayloadNonce{NonceData: nr},
	}}
	raw, err := response.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(raw, address); err != nil {
		t.Fatal(err)
	}
	keys := independentSHA256Keys(secret, append(nonces, nr...), header)
	count, _, err = peer.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	firstAuth, err := ikev2.DecodeHeader(buffer[:count])
	if err != nil || firstAuth.ExchangeType != ikev2.IKE_AUTH || firstAuth.MessageID != 1 {
		t.Fatal("missing initial AUTH")
	}
	responder := diagnosticResponder{header: *header, keys: keys}
	identityRequest := (&eap.EAPPacket{Code: 1, Identifier: 41, Type: 1, Data: []byte("PRIVATE-IDENTITY-REQUEST")}).Encode()
	if _, err := peer.WriteToUDP(responder.protect(t, identityRequest), address); err != nil {
		t.Fatal(err)
	}
	count, _, err = peer.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	identityResponse := diagnosticDecrypt(t, buffer[:count], keys)
	if identityResponse[28] != byte(ikev2.EAP) {
		t.Fatal("second AUTH has no EAP")
	}
	plain := identityResponse[36:]
	packet, err := eap.Parse(plain)
	if err != nil || packet.Code != 2 || packet.Type != 1 || packet.Identifier != 41 || !bytes.Equal(packet.Data, []byte(buildNAI("001010000000001", cfg))) {
		t.Fatal("identity response changed")
	}
	if _, err := peer.WriteToUDP(responder.protect(t, (&eap.EAPPacket{Code: 4, Identifier: 41}).Encode()), address); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err == nil || !strings.Contains(err.Error(), "unexpected EAP Code: 4") {
		t.Fatal("terminal failure behavior changed")
	}
	if provider.akaCalls != 0 || provider.imsiCalls != 1 {
		t.Fatal("identity-only flow changed SIM calls")
	}
	events := diagnosticEvents(t, output)
	want := []diagnosticEvent{
		{Message: "EAP stage", Direction: "received", Code: 1, Type: 1, AttrTypes: []int{}},
		{Message: "EAP stage", Direction: "send_attempt", Code: 2, Type: 1, AttrTypes: []int{}},
		{Message: "EAP stage", Direction: "received", Code: 4, Terminal: "eap_failure", AttrTypes: []int{}},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unexpected production event sequence: %+v", events)
	}
	assertDiagnosticPrivacy(t, output, []byte("PRIVATE-"), []byte("001010000000001"))
}

type diagnosticResponder struct {
	header ikev2.IKEHeader
	keys   []byte
}

func (responder *diagnosticResponder) protect(t *testing.T, eapRaw []byte) []byte {
	t.Helper()
	responder.header.MessageID++
	responder.header.ExchangeType = ikev2.IKE_AUTH
	responder.header.NextPayload = ikev2.SK
	plain := []byte{0, 0}
	plain = binary.BigEndian.AppendUint16(plain, uint16(4+len(eapRaw)))
	plain = append(plain, eapRaw...)
	pad := (16 - (len(plain)+1)%16) % 16
	plain = append(plain, make([]byte, pad)...)
	plain = append(plain, byte(pad))
	iv := bytes.Repeat([]byte{3}, 16)
	block, err := aes.NewCipher(responder.keys[128:160])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	responder.header.Length = uint32(28 + 4 + 16 + len(plain) + 16)
	raw := responder.header.Encode()
	raw = append(raw, byte(ikev2.EAP), 0)
	raw = binary.BigEndian.AppendUint16(raw, uint16(4+16+len(plain)+16))
	raw = append(raw, iv...)
	raw = append(raw, plain...)
	mac := hmac.New(sha256.New, responder.keys[64:96])
	mac.Write(raw)
	return append(raw, mac.Sum(nil)[:16]...)
}

func diagnosticDecrypt(t *testing.T, raw, keys []byte) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, keys[32:64])
	mac.Write(raw[:len(raw)-16])
	if !hmac.Equal(mac.Sum(nil)[:16], raw[len(raw)-16:]) {
		t.Fatal("invalid response ICV")
	}
	block, err := aes.NewCipher(keys[96:128])
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(raw)-64)
	cipher.NewCBCDecrypter(block, raw[32:48]).CryptBlocks(plain, raw[48:len(raw)-16])
	plain = plain[:len(plain)-1-int(plain[len(plain)-1])]
	return append(bytes.Clone(raw[:28]), append(raw[28:32:32], plain...)...)
}
