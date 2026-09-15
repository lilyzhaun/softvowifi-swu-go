package swu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"net"
	"testing"
	"time"
)

func Test_AKAIdentity_actualUDP_whenChallengeFollowsIdentity(t *testing.T) {
	for _, scenario := range []string{"valid", "invalid-checkcode"} {
		t.Run(scenario, func(t *testing.T) {
			peer := newAKAWirePeer(t)
			sess, provider := identitySession(t)
			log, output := diagnosticLogger()
			sess.Logger = log
			sess.cfg.LocalAddr = "127.0.0.1"
			sess.cfg.EpDGAddr = "127.0.0.1"
			sess.cfg.EpDGPort = uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)
			sess.cfg.APN = "ims"
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			finished := make(chan error, 1)
			t.Cleanup(func() {
				cancel()
				sess.Shutdown()
			})
			go func() { finished <- sess.Connect(ctx) }()
			peer.negotiate(t)
			assertAKAWireInitial(t, peer.decrypt(t, peer.receive(t)))
			request := identityRequest(0xcd, 13, 1, 0x12, 0x34)
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: request}}))
			identityPayloads := peer.decrypt(t, peer.receive(t))
			if len(identityPayloads) != 1 || identityPayloads[0].kind != 48 ||
				!bytes.Equal(identityPayloads[0].body, identityResponse(0xcd, identityNAI)) {
				t.Fatal("actual UDP Identity response differs from independent wire bytes")
			}
			digest := sha1.Sum(append(bytes.Clone(request), identityPayloads[0].body...))
			checkcode := append([]byte{134, 6, 0, 0}, digest[:]...)
			if scenario == "invalid-checkcode" {
				checkcode[4] ^= 1
			}
			keys := referenceAKAKeys(provider, false)
			challenge := identityChallenge(t, keys[16:32], checkcode)
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: challenge}}))
			payloads := peer.decrypt(t, peer.receive(t))
			if len(payloads) != 1 || payloads[0].kind != 48 {
				t.Fatal("expected one EAP response on UDP")
			}
			if scenario == "valid" {
				want := referenceHex(t, "02ce003017010000030500802b1c2593f5af288a3766cada9ce23fb90b05000000000000000000000000000000000000")
				mac := hmac.New(sha1.New, keys[16:32])
				mac.Write(want)
				copy(want[len(want)-16:], mac.Sum(nil)[:16])
				if !bytes.Equal(payloads[0].body, want) {
					t.Fatal("actual UDP Challenge response differs from independent AOSP-derived vector")
				}
				if err := verifyAKAWireMAC(payloads[0].body, keys[16:32]); err != nil {
					t.Fatal(err)
				}
			} else if !bytes.Equal(payloads[0].body, []byte{2, 0xce, 0, 12, 23, 14, 0, 0, 22, 1, 0, 0}) {
				t.Fatal("invalid CHECKCODE did not produce client error on UDP")
			}
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{4, 0xce, 0, 4}}}))
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("synthetic terminal Failure was accepted")
				}
			case <-ctx.Done():
				t.Fatal("Connect did not stop on Failure")
			}
			if scenario == "invalid-checkcode" && (provider.calls != 0 || len(sess.MSK) != 0) {
				t.Fatal("invalid CHECKCODE invoked SIM or installed MSK")
			}
			assertDiagnosticPrivacy(t, output, []byte(identityNAI), provider.res, provider.ck, provider.ik)
			t.Log("actual encrypted UDP AUTH1/2/3, independent outer ICV and Identity wire verified; synthetic terminal Failure consumed")
		})
	}
}
