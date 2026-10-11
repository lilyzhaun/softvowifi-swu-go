package swu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func Test_AKAIdentity_initiatorAUTHUsesOriginalIDi_whenInnerPermanent(t *testing.T) {
	testAKAIdentityAUTH(t, "unfragmented")
}

func TestFragmentConnectCompletesLongIndependentAUTH(t *testing.T) {
	for _, layout := range []string{"ordered", "reordered"} {
		t.Run(layout, func(t *testing.T) { testAKAIdentityAUTH(t, layout) })
	}
}

func TestNotificationConnectProtectedSuccessThenAUTH(t *testing.T) {
	testAKAIdentityAUTH(t, "notification")
}

func TestAUTHRoundConnectCoPayloadReachesFinalAUTH(t *testing.T) {
	for _, layout := range []string{"device41101", "device16432"} {
		t.Run(layout, func(t *testing.T) { testAKAIdentityAUTH(t, layout) })
	}
}

func testAKAIdentityAUTH(t *testing.T, layout string) {
	t.Helper()
	peer := newAKAWirePeer(t)
	send := func(payloads []akaWirePayload) {
		if layout == "unfragmented" || layout == "notification" || strings.HasPrefix(layout, "device") {
			peer.send(t, peer.protect(t, payloads))
			return
		}
		peer.sendFragmented(t, payloads, layout == "reordered")
	}
	sess, provider := identitySession(t)
	sess.cfg.FastReauthID = "original-pseudonym@public.invalid"
	sess.cfg.LocalAddr, sess.cfg.EpDGAddr = "127.0.0.1", "127.0.0.1"
	sess.cfg.EpDGPort = uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)
	sess.cfg.APN = "ims"
	if strings.HasPrefix(layout, "device") {
		sess.cfg.IMEI = "123456789012345"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	finished := make(chan struct{})
	established := make(chan struct{})
	sess.Logger = sess.Logger.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "会话已建立" {
			close(established)
		}
		return nil
	}))
	var connectErr error
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
			sess.Shutdown()
		case <-time.After(5 * time.Second):
			t.Error("Connect did not stop")
		}
	})
	go func() { connectErr = sess.Connect(ctx); close(finished) }()
	peer.negotiate(t)
	initial := peer.decrypt(t, peer.receive(t))
	if len(initial) == 0 || initial[0].kind != 35 {
		t.Fatal("missing AUTH1 IDi")
	}
	idiBody := bytes.Clone(initial[0].body)
	wantIDi := append([]byte{3, 0, 0, 0}, []byte("original-pseudonym@public.invalid")...)
	if !bytes.Equal(idiBody, wantIDi) {
		t.Fatal("fixture must emit pseudonym IDi")
	}
	identityReq := identityRequest(0xcd, 10, 1, 0, 0)
	send([]akaWirePayload{{kind: 48, body: identityReq}})
	identityResp := peer.decrypt(t, peer.receive(t))
	if len(identityResp) != 1 || !bytes.Equal(identityResp[0].body, identityResponse(0xcd, identityNAI)) {
		t.Fatal("inner permanent Identity response differs")
	}
	digest := sha1.Sum(append(bytes.Clone(identityReq), identityResp[0].body...))
	keys := referenceAKAKeys(provider, false)
	challenge := identityChallenge(t, keys[16:32], append([]byte{134, 6, 0, 0}, digest[:]...))
	if layout == "notification" {
		challenge = append(challenge, 135, 1, 0, 0)
		binary.BigEndian.PutUint16(challenge[2:4], uint16(len(challenge)))
		for offset := 8; offset < len(challenge); offset += int(challenge[offset+1]) * 4 {
			if challenge[offset] == 11 {
				clear(challenge[offset+4 : offset+20])
				m := hmac.New(sha1.New, keys[16:32])
				m.Write(challenge)
				copy(challenge[offset+4:offset+20], m.Sum(nil)[:16])
				break
			}
		}
	}
	challengePayloads := []akaWirePayload{{kind: 48, body: challenge}}
	identityCode := uint16(41101)
	if layout == "device16432" {
		identityCode = 16432
	}
	if strings.HasPrefix(layout, "device") {
		challengePayloads = append(challengePayloads, akaWirePayload{kind: 41, body: independentNotifyBody(identityCode, []byte{0, 1, 1})})
	}
	send(challengePayloads)
	response := peer.decrypt(t, peer.receive(t))
	wantCount := 1
	if strings.HasPrefix(layout, "device") {
		wantCount = 2
	}
	if len(response) != wantCount || response[0].body[5] != 1 {
		t.Fatal("missing Challenge response")
	}
	if strings.HasPrefix(layout, "device") {
		want := referenceHex(t, "0100a08d00090121436587092143f5")
		binary.BigEndian.PutUint16(want[2:4], identityCode)
		if response[1].kind != 41 || !bytes.Equal(response[1].body, want) {
			t.Fatal("Connect omitted/mutated requested equipment identity in the same verified Challenge round")
		}
	}
	if err := verifyAKAWireMAC(response[0].body, keys[16:32]); err != nil {
		t.Fatal(err)
	}
	successID := byte(0xce)
	if layout == "notification" {
		send([]akaWirePayload{{kind: 48, body: notificationWire(0x8000, keys[16:32])}})
		ack := peer.decrypt(t, peer.receive(t))
		if len(ack) != 1 || ack[0].kind != 48 {
			t.Fatal("normal Connect did not ACK protected success")
		}
		notificationACK(t, []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: ack[0].body}}, keys[16:32])
		successID = 0x87
	}
	idrBody := append([]byte{2, 0, 0, 0}, []byte(testIDrFQDN)...)
	send([]akaWirePayload{
		{kind: 36, body: idrBody}, {kind: 48, body: []byte{3, successID, 0, 4}},
	})
	authPayloads := peer.decrypt(t, peer.receive(t))
	if len(authPayloads) != 1 || authPayloads[0].kind != 39 || len(authPayloads[0].body) != 36 || authPayloads[0].body[0] != 2 {
		t.Fatal("EAP Success did not produce shared-key initiator AUTH")
	}
	actualAUTH := authPayloads[0].body[4:]
	authKey := independentHMACSHA256(keys[32:96], []byte("Key Pad for IKEv2"))
	signed := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
	signed = append(signed, independentHMACSHA256(peer.keys[160:192], idiBody)...)
	expected := independentHMACSHA256(authKey, signed)
	wrongSigned := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
	wrongSigned = append(wrongSigned, independentHMACSHA256(peer.keys[160:192], append([]byte{3, 0, 0, 0}, []byte(identityNAI)...))...)
	if !bytes.Equal(actualAUTH, expected) || bytes.Equal(actualAUTH, independentHMACSHA256(authKey, wrongSigned)) {
		t.Error("initiator AUTH must bind original pseudonym IDi, not inner permanent NAI")
	}
	responderAUTH := independentResponderAUTH(keys[32:96], peer.keys[192:224], idrBody, peer.initResponse, peer.initiatorNonce)
	childBody, err := testChildSA().Encode()
	if err != nil {
		t.Fatal(err)
	}
	final := []akaWirePayload{
		{kind: 39, body: append([]byte{2, 0, 0, 0}, responderAUTH...)},
		{kind: 47, body: []byte{2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 10}},
		{kind: 33, body: childBody},
		{kind: 44, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 192, 0, 2, 10, 192, 0, 2, 10}},
		{kind: 45, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255}},
	}
	if layout != "unfragmented" && layout != "notification" && !strings.HasPrefix(layout, "device") {
		final = append(final, akaWirePayload{kind: 41, body: independentNotifyBody(16432, bytes.Repeat([]byte{0x71}, 3000))})
	}
	send(final)
	select {
	case <-established:
		cancel()
		<-finished
	case <-ctx.Done():
		t.Fatal("Connect did not establish session after responder AUTH")
	}
	if !errors.Is(connectErr, context.Canceled) || sess.ChildSAOut == nil || !bytes.Equal(sess.MSK, keys[32:96]) {
		t.Fatalf("full authentication did not establish Child SA: %v", connectErr)
	}
	t.Log("UDP Identity -> Challenge -> EAP Success -> independently checked initiator/responder AUTH -> Child SA established")
}

func Test_AKAIdentity_AUTHRequiresCapturedIDi(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	sess.resetIKEAuthTranscripts()
	if _, err := sess.buildIKEAuthFinalPayloads(); err == nil {
		t.Fatal("final AUTH reconstructed an IDi that was never captured")
	}
}

func Test_AKAIdentity_AUTH1BodyOwnedAndAttemptScoped(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	sess.resetIKEAuthTranscripts()
	sess.cfg.FastReauthID = "immutable-pseudonym@public.invalid"
	payloads, err := sess.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	identity := payloads[0].(*ikev2.EncryptedPayloadID)
	body, err := identity.Encode()
	if err != nil {
		t.Fatal(err)
	}
	identity.IDData[0] ^= 1
	identityEAP(t, sess, []byte{1, 1, 0, 5, 1})
	auth, err := sess.buildIKEAuthFinalPayloads()
	if err != nil {
		t.Fatal(err)
	}
	want := independentResponderAUTH(sess.MSK, sess.Keys.SK_pi, body, sess.msgBuffer, sess.nr)
	if !bytes.Equal(auth[0].(*ikev2.EncryptedPayloadAuth).AuthData, want) {
		t.Fatal("returned payload or Type1 identity mutated saved AUTH1 body")
	}
	sess.resetIKEAuthTranscripts()
	if _, err := sess.buildIKEAuthFinalPayloads(); err == nil {
		t.Fatal("attempt reset retained AUTH1 IDi")
	}
}

func Test_AKAIdentity_AUTH1RejectsChangedBodyWithinAttempt(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	original := bytes.Clone(sess.localIDiBody)
	sess.cfg.FastReauthID = "different-pseudonym@public.invalid"
	payloads, err := sess.buildIKEAuthInitPayloads()
	if err == nil || len(payloads) != 0 || !bytes.Equal(sess.localIDiBody, original) {
		t.Fatal("second AUTH1 changed frozen IDi body")
	}
}
