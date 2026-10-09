package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func Test_InitCookieRetryIsFirstAndPreservesOtherBytes(t *testing.T) {
	for _, layout := range []string{"", ikev2.ProposalLayoutSingleCombined} {
		for _, size := range []int{1, 20, 64} {
			t.Run(fmt.Sprintf("%s/%d", layout, size), func(t *testing.T) {
				sess := newInitTestSession(layout)
				initial, err := sess.buildIKESAInitPacket()
				if err != nil {
					t.Fatal(err)
				}
				if initial[16] != byte(ikev2.SA) {
					t.Fatal("initial request must remain SA-first without a Cookie")
				}
				for _, value := range []byte{7, 9} {
					// Explicitly synthetic challenge; never a live server Cookie.
					cookie := bytes.Repeat([]byte{value}, size)
					response := ikev2.NewIKEPacket()
					response.Header.SPIi = sess.SPIi
					response.Header.Version = 0x20
					response.Header.ExchangeType = ikev2.IKE_SA_INIT
					response.Header.Flags = ikev2.FlagResponse
					response.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: cookie}}
					raw, err := response.Encode()
					if err != nil {
						t.Fatal(err)
					}
					if err := sess.handleIKESAInitResp(raw, sess.msgBuffer); !errors.Is(err, ErrCookieRequired) {
						t.Fatalf("challenge did not request retry: %v", err)
					}
					retry, err := sess.buildIKESAInitPacket()
					if err != nil {
						t.Fatal(err)
					}
					packet, err := ikev2.DecodePacket(retry)
					if err != nil {
						t.Fatal(err)
					}
					first, ok := packet.Payloads[0].(*ikev2.EncryptedPayloadNotify)
					if retry[16] != byte(ikev2.N) || !ok || first.NotifyType != ikev2.COOKIE || !bytes.Equal(first.NotifyData, cookie) {
						t.Fatal("RFC7296 COOKIE must be the first retry payload")
					}
					cookieLength := int(binary.BigEndian.Uint16(retry[30:32]))
					if cookieLength != 8+size || !bytes.Equal(retry[28+cookieLength:], initial[28:]) {
						t.Fatal("Cookie retry changed another payload or inserted a second Cookie")
					}
					if !bytes.Equal(retry[:16], initial[:16]) || !bytes.Equal(retry[17:24], initial[17:24]) || len(retry) != len(initial)+cookieLength {
						t.Fatal("Cookie retry changed SPI, exchange, version, flags, message ID, or body length")
					}
					if sess.SPIr != 0 || sess.Keys != nil || sess.SequenceNumber.Load() != 0 {
						t.Fatal("Cookie challenge advanced the authenticated state")
					}
				}
			})
		}
	}
}

func Test_ConnectCookieRetryStartsWithCookieOverUDP(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{EpDGAddr: "127.0.0.1", LocalAddr: "127.0.0.1", EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port)}
	cfg.TransportFactory = func(local, remote string) (Transport, error) {
		return ipsec.NewSocketManager(local, remote, "127.0.0.1:1")
	}
	sess := NewSession(cfg, zap.NewNop())
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	finished := make(chan error, 1)
	go func() { finished <- sess.Connect(ctx); close(finished) }()
	t.Cleanup(func() { cancel(); sess.Shutdown(); <-finished })
	var firstBody []byte
	for attempt := 0; attempt < 2; attempt++ {
		buffer := make([]byte, 4096)
		count, client, err := peer.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := ikev2.DecodePacket(buffer[:count])
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 1 {
			cookie, ok := packet.Payloads[0].(*ikev2.EncryptedPayloadNotify)
			if !ok || cookie.NotifyType != ikev2.COOKIE || !bytes.Equal(cookie.NotifyData, []byte{1, 2, 3, 4}) {
				t.Fatal("production Connect sent a misplaced Cookie over UDP")
			}
			length := int(binary.BigEndian.Uint16(buffer[30:32]))
			if !bytes.Equal(buffer[28+length:count], firstBody) {
				t.Fatal("production Cookie retry changed non-Cookie payload bytes")
			}
			break
		}
		firstBody = bytes.Clone(buffer[28:count])
		response := ikev2.NewIKEPacket()
		response.Header = packet.Header
		response.Header.Flags = ikev2.FlagResponse
		response.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{1, 2, 3, 4}}}
		raw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(raw, client); err != nil {
			t.Fatal(err)
		}
	}
}
