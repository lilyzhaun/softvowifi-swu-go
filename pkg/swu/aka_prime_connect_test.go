package swu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestPrimeConnectPublishedVectorReachesFinalAUTH(t *testing.T) {
	for _, result := range []bool{false, true} {
		peer := newAKAWirePeer(t)
		v := primeStandardVectors[0]
		s, p := primeStandardSession(t, v)
		s.cfg.FastReauthID = primePublicIdentity
		s.cfg.LocalAddr, s.cfg.EpDGAddr = "127.0.0.1", "127.0.0.1"
		s.cfg.EpDGPort = uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)
		s.cfg.APN = "ims"
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		done := make(chan struct{})
		established := make(chan struct{})
		s.Logger = s.Logger.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
			if entry.Message == "会话已建立" {
				close(established)
			}
			return nil
		}))
		var connectErr error
		go func() { connectErr = s.Connect(ctx); close(done) }()
		t.Cleanup(func() {
			cancel()
			s.Shutdown()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("Prime Connect did not stop")
			}
		})
		peer.negotiate(t)
		initial := peer.decrypt(t, peer.receive(t))
		if len(initial) != 8 || !bytes.Equal(initial[0].body, append([]byte{3, 0, 0, 0}, []byte(primePublicIdentity)...)) {
			t.Fatal("actual original IDi changed before Prime Challenge")
		}
		peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: primeStandardRequest(t, v, result, 1)}}))
		response := peer.decrypt(t, peer.receive(t))
		if len(response) != 1 || !bytes.Equal(response[0].body, primeExpectedResponse(t, v, result)) {
			t.Fatal("normal Connect did not transmit published-vector Prime response")
		}
		material := referenceHex(t, v.material)
		successID := byte(0x93)
		if result {
			raw := []byte{1, 0x87, 0, 32, 50, 12, 0, 0, 12, 1, 0x80, 0, 11, 5, 0, 0}
			raw = append(raw, make([]byte, 16)...)
			mac := hmac.New(sha256.New, material[16:48])
			mac.Write(raw)
			copy(raw[16:32], mac.Sum(nil)[:16])
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: raw}}))
			ack := peer.decrypt(t, peer.receive(t))
			want := []byte{2, 0x87, 0, 28, 50, 12, 0, 0, 11, 5, 0, 0}
			want = append(want, make([]byte, 16)...)
			mac = hmac.New(sha256.New, material[16:48])
			mac.Write(want)
			copy(want[12:], mac.Sum(nil)[:16])
			if len(ack) != 1 || !bytes.Equal(ack[0].body, want) {
				t.Fatal("real Prime negotiated result ACK changed method MAC")
			}
			successID = 0x87
		}
		idr := append([]byte{2, 0, 0, 0}, []byte(testIDrFQDN)...)
		peer.send(t, peer.protect(t, []akaWirePayload{{kind: 36, body: idr}, {kind: 48, body: []byte{3, successID, 0, 4}}}))
		finalRequest := peer.decrypt(t, peer.receive(t))
		key := independentHMACSHA256(material[80:144], []byte("Key Pad for IKEv2"))
		signed := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
		signed = append(signed, independentHMACSHA256(peer.keys[160:192], initial[0].body)...)
		if len(finalRequest) != 1 || finalRequest[0].kind != 39 || !bytes.Equal(finalRequest[0].body, append([]byte{2, 0, 0, 0}, independentHMACSHA256(key, signed)...)) {
			t.Fatal("Prime MSK/original IDi not bound by independent initiator AUTH")
		}
		auth := independentResponderAUTH(material[80:144], peer.keys[192:224], idr, peer.initResponse, peer.initiatorNonce)
		child, err := testChildSA().Encode()
		if err != nil {
			t.Fatal(err)
		}
		peer.send(t, peer.protect(t, []akaWirePayload{
			{kind: 39, body: append([]byte{2, 0, 0, 0}, auth...)},
			{kind: 47, body: []byte{2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 10}},
			{kind: 33, body: child},
			{kind: 44, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 192, 0, 2, 10, 192, 0, 2, 10}},
			{kind: 45, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255}},
		}))
		select {
		case <-established:
			cancel()
			<-done
		case <-ctx.Done():
			t.Fatal("Prime independent final responder AUTH did not establish")
		}
		if !errors.Is(connectErr, context.Canceled) || s.ChildSAOut == nil || p.calls != 1 || !bytes.Equal(s.MSK, material[80:144]) {
			t.Fatal("full published-vector Prime wire did not establish Child with one SIM call")
		}
	}
}
