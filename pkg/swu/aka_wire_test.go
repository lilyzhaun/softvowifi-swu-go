package swu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

type akaWireSIM struct {
	vectorSIM
	rand, autn []byte
}

func (provider *akaWireSIM) CalculateAKA(rand, autn []byte) ([]byte, []byte, []byte, []byte, error) {
	provider.rand, provider.autn = bytes.Clone(rand), bytes.Clone(autn)
	if !bytes.Equal(rand, bytes.Repeat([]byte{0x10}, 16)) || !bytes.Equal(autn, bytes.Repeat([]byte{0x20}, 16)) {
		return nil, nil, nil, nil, errors.New("software SIM received different synthetic challenge")
	}
	return provider.vectorSIM.CalculateAKA(rand, autn)
}

func Test_ConnectSendsIndependentAKAResponse_whenUDPPeerChallenges(t *testing.T) {
	for _, scenario := range []struct {
		size int
		imei string
	}{{4, ""}, {5, ""}, {8, ""}, {16, ""}, {8, "123456789012345"}} {
		t.Run(fmt.Sprintf("RES%d/device_identity_%t", scenario.size, scenario.imei != ""), func(t *testing.T) {
			size := scenario.size
			peer := newAKAWirePeer(t)
			provider := &akaWireSIM{vectorSIM: vectorSIM{
				res: make([]byte, size), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16),
			}}
			for index := range provider.res {
				provider.res[index] = byte(0x60 + index)
			}
			keys := referenceAKAKeys(&provider.vectorSIM, false)
			challenge := referenceChallenge(keys[16:32], false)
			want := referenceResponse(bytes.Clone(provider.res), keys[16:32], false)
			if err := verifyAKAWireMAC(challenge, keys[16:32]); err != nil {
				t.Fatal(err)
			}
			log, output := diagnosticLogger()
			sess := NewSession(&Config{
				LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1",
				EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), APN: "ims", SIM: provider,
				IMEI: scenario.imei,
			}, log)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			finished := make(chan struct{})
			var connectErr error
			t.Cleanup(func() {
				cancel()
				select {
				case <-finished:
					sess.Shutdown()
				case <-time.After(5 * time.Second):
					t.Error("Connect did not stop after cancellation")
				}
			})

			go func() { connectErr = sess.Connect(ctx); close(finished) }()
			peer.negotiate(t)
			initial := peer.decrypt(t, peer.receive(t))
			if scenario.imei != "" {
				if len(initial) != 9 || initial[8].kind != 41 || !bytes.Equal(initial[8].body, referenceHex(t, "0000a08d00090121436587092143f5")) {
					t.Fatal("AUTH1 must append exactly one type-1 IMEI device identity notification")
				}
				initial = initial[:8]
			}
			assertAKAWireInitial(t, initial)
			peer.send(t, peer.protect(t, []akaWirePayload{
				{kind: 36, body: append([]byte{2, 0, 0, 0}, []byte("epdg.example.invalid")...)},
				{kind: 48, body: challenge},
			}))
			outgoing := peer.receive(t)
			payloads := peer.decrypt(t, outgoing)

			if len(payloads) != 1 || payloads[0].kind != 48 {
				t.Fatal("AUTH2 must contain exactly one EAP payload")
			}
			actual := payloads[0].body
			if !bytes.Equal(actual, want) {
				t.Fatal("actual UDP AUTH2 EAP differs byte-for-byte from independent response")
			}
			if err := verifyAKAWireMAC(actual, keys[16:32]); err != nil {
				t.Fatal(err)
			}
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{4, 0xa7, 0, 4}}}))
			select {
			case <-finished:
			case <-ctx.Done():
				t.Fatal("Connect did not consume peer EAP Failure")
			}
			if connectErr == nil || connectErr.Error() != "unexpected EAP Code: 4" {
				t.Fatalf("unexpected terminal result: %v", connectErr)
			}
			if provider.calls != 1 || !bytes.Equal(provider.rand, bytes.Repeat([]byte{0x10}, 16)) || !bytes.Equal(provider.autn, bytes.Repeat([]byte{0x20}, 16)) {
				t.Fatal("wire challenge was not passed unchanged to software SIM exactly once")
			}
			events := structureEvents(t, output)
			if len(events) != 3 {
				t.Fatal("missing actual challenge/verification/response checkpoints")
			}
			request, verified, response := events[0], events[1], events[2]
			if request.CheckcodeEmpty == nil || !*request.CheckcodeEmpty || request.BiddingD == nil || *request.BiddingD || !verified.Verified || verified.DerivationOrder != "ik_ck" {
				t.Fatal("did not exercise empty CHECKCODE, D=false and verified IK||CK branch")
			}
			if response.RESOctets == nil || *response.RESOctets != size || response.RESBits == nil || *response.RESBits != size*8 ||
				response.LocalMACValid == nil || !*response.LocalMACValid || response.PaddingZero == nil || !*response.PaddingZero ||
				response.IdentifierMatches == nil || !*response.IdentifierMatches {
				t.Fatal("local structure checkpoint differs from independently verified wire response")
			}
			assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik, provider.rand, provider.autn)
			if scenario.imei != "" {
				assertDiagnosticPrivacy(t, output, []byte(scenario.imei), referenceHex(t, "21436587092143f5"))
			}
			t.Logf("UDP AUTH1/2 ids=1/2; fourth suite; RES=%d; EAP=%d bytes exact; outer ICV and independent EAP MAC valid; peer Failure consumed", size, len(actual))
		})
	}
}
