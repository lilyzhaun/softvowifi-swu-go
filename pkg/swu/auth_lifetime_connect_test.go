package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestConnectAuthenticatedLifetimeAndCPOrderKeepIndependentAUTH(t *testing.T) {
	for _, reordered := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "ike_scope_cp_last"}[reordered], func(t *testing.T) {
			peer := newAKAWirePeer(t)
			provider := &akaWireSIM{vectorSIM: vectorSIM{res: []byte{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67}, ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}}
			material := referenceAKAKeys(&provider.vectorSIM, false)
			log, output := diagnosticLogger()
			established := make(chan struct{})
			log = log.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
				if entry.Message == "会话已建立" {
					close(established)
				}
				return nil
			}))
			s := NewSession(&Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), APN: "ims", SIM: provider}, log)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			done := make(chan error, 1)
			go func() { done <- s.Connect(ctx) }()
			t.Cleanup(func() { cancel(); s.Shutdown() })
			peer.negotiate(t)
			initial := peer.decrypt(t, peer.receive(t))
			assertAKAWireInitial(t, initial)
			idr := append([]byte{2, 0, 0, 0}, []byte(testIDrFQDN)...)
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 36, body: idr}, {kind: 48, body: referenceChallenge(material[16:32], false)}}))
			response := peer.decrypt(t, peer.receive(t))
			if len(response) != 1 || response[0].kind != 48 || !bytes.Equal(response[0].body, referenceResponse(provider.res, material[16:32], false)) {
				t.Fatal("compatibility changed independent AKA response")
			}
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{3, 0xa7, 0, 4}}}))
			final := peer.decrypt(t, peer.receive(t))
			key := independentHMACSHA256(material[32:96], []byte("Key Pad for IKEv2"))
			signed := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
			signed = append(signed, independentHMACSHA256(peer.keys[160:192], initial[0].body)...)
			if len(final) != 1 || final[0].kind != 39 || !bytes.Equal(final[0].body, append([]byte{2, 0, 0, 0}, independentHMACSHA256(key, signed)...)) {
				t.Fatal("initiator AUTH no longer binds original IDi and transcript")
			}
			auth := independentResponderAUTH(material[32:96], peer.keys[192:224], idr, peer.initResponse, peer.initiatorNonce)
			child, err := testChildSA().Encode()
			if err != nil {
				t.Fatal(err)
			}
			cp := akaWirePayload{kind: 47, body: []byte{2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 10}}
			notify := akaWirePayload{kind: 41, body: []byte{0, 0, 0x40, 0x13, 0, 0, 0x0e, 0x10}}
			payloads := []akaWirePayload{
				{kind: 39, body: append([]byte{2, 0, 0, 0}, auth...)}, cp,
				{kind: 33, body: child},
				{kind: 44, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 192, 0, 2, 10, 192, 0, 2, 10}},
				{kind: 45, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255}}, notify,
			}
			if reordered {
				notify.body[0] = 1
				payloads = []akaWirePayload{notify, payloads[2], payloads[0], payloads[3], payloads[4], cp}
			}
			peer.send(t, peer.protect(t, payloads))
			select {
			case <-established:
			case err := <-done:
				t.Fatalf("normal Connect rejected authenticated final representation: %v", err)
			case <-ctx.Done():
				t.Fatal("normal Connect did not establish before deadline")
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) || s.ChildSAIn == nil || s.ChildSAOut == nil || s.authLifetime != 3600 || provider.calls != 1 {
				t.Fatal("normal Connect did not establish complete Child with one SIM invocation")
			}
			assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik, provider.rand, provider.autn)
		})
	}
}
