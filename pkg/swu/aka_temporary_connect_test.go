package swu

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// A real UDP Connect, including independently encoded/decrypted IKE and both
// final AUTHs. The only stored values are synthetic; no SIM or carrier is used.
func temporaryIdentityConnect(t *testing.T, previous *AKATemporaryIdentity, mode, nextID string, counter uint16) *AKATemporaryIdentity {
	t.Helper()
	peer := newAKAWirePeer(t)
	base, provider := identitySession(t)
	cfg := base.cfg
	cfg.LocalAddr, cfg.EpDGAddr, cfg.APN = "127.0.0.1", "127.0.0.1", "ims"
	cfg.EpDGPort = uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)
	cfg.TemporaryIdentity = previous.clone()
	updates := make(chan *AKATemporaryIdentity, 4)
	cfg.OnTemporaryIdentityUpdate = func(v *AKATemporaryIdentity) error { updates <- v.clone(); return nil }
	s := NewSession(cfg, base.Logger)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	finished := make(chan error, 1)
	go func() { finished <- s.Connect(ctx) }()
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Error("Connect did not release ownership")
			}
		}
		s.Shutdown()
	})
	peer.negotiate(t)
	initial := peer.decrypt(t, peer.receive(t))
	if len(initial) == 0 || initial[0].kind != 35 {
		t.Fatal("missing actual AUTH1")
	}
	idi := initial[0].body
	identity := string(idi[4:])
	fast := previous != nil && previous.ReauthID != ""
	if fast {
		select {
		case retired := <-updates:
			if retired.ReauthID != "" || len(retired.MK) != 0 || identity != previous.ReauthID {
				t.Fatal("identity appeared on wire before durable retirement")
			}
		default:
			t.Fatal("missing synchronous retirement before AUTH1")
		}
	}
	assertNoPublication := func() {
		t.Helper()
		select {
		case <-updates:
			t.Fatal("new identity published before final responder AUTH")
		default:
		}
	}
	assertNoPublication()
	var msk, mk, kEncr, kAut []byte
	if fast {
		nonce := bytes.Repeat([]byte{0x33}, 16)
		inner := append([]byte{eap.AT_COUNTER, 1, byte(counter >> 8), byte(counter), eap.AT_NONCE_S, 5, 0, 0}, nonce...)
		if nextID != "" {
			inner = append(inner, independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, nextID)...)
		}
		raw := independentProtectedAKARequest(t, 13, inner, previous.KEncr, previous.KAut, nil)
		peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: raw}}))
		response := peer.decrypt(t, peer.receive(t))
		if len(response) != 1 || response[0].kind != 48 {
			t.Fatal("missing fast response")
		}
		assertEncryptedReauthResponse(t, []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: response[0].body}}, counter, nonce, previous.KEncr, previous.KAut, mode == "fallback")
		h := sha1.New()
		h.Write([]byte(identity))
		h.Write([]byte{byte(counter >> 8), byte(counter)})
		h.Write(nonce)
		h.Write(previous.MK)
		msk = referenceExpansion(h.Sum(nil))[:64]
		mk, kEncr, kAut = previous.MK, previous.KEncr, previous.KAut
		assertNoPublication()
	}
	if !fast || mode == "fallback" {
		h := sha1.New()
		h.Write([]byte(identity))
		if mode == "full-ckik" {
			h.Write(provider.ck)
			h.Write(provider.ik)
		} else {
			h.Write(provider.ik)
			h.Write(provider.ck)
		}
		mk = h.Sum(nil)
		material := referenceExpansion(mk)
		kEncr, kAut, msk = material[:16], material[16:32], material[32:96]
		base := identityChallenge(t, kAut, nil)
		inner := independentIdentityAttribute(eap.AT_NEXT_PSEUDONYM, "next-pseudonym")
		if nextID != "" {
			inner = append(inner, independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, nextID)...)
		}
		raw := independentProtectedAKARequest(t, 1, inner, kEncr, kAut, base[8:len(base)-20])
		peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: raw}}))
		response := peer.decrypt(t, peer.receive(t))
		if len(response) != 1 || response[0].body[5] != 1 || verifyAKAWireMAC(response[0].body, kAut) != nil {
			t.Fatal("missing independently verified full Challenge response")
		}
		assertNoPublication()
	}
	if mode == "cancel-before-auth" {
		cancel()
		err := <-finished
		joined = true
		if !errors.Is(err, context.Canceled) || s.akaPending != nil {
			t.Fatal("cancellation retained a pending identity")
		}
		assertNoPublication()
		return nil
	}
	if mode == "notification-failure" {
		raw := independentProtectedAKARequest(t, eap.SubtypeNotificationAlt,
			[]byte{eap.AT_COUNTER, 1, byte(counter >> 8), byte(counter)}, kEncr, kAut, []byte{eap.AT_NOTIFICATION, 1, 0, 0})
		peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: raw}}))
		ack := peer.decrypt(t, peer.receive(t))
		if len(ack) != 1 || verifyAKAWireMAC(ack[0].body, kAut) != nil {
			t.Fatal("missing protected failure acknowledgement")
		}
		assertNoPublication()
	}
	if mode == "eap-failure" || mode == "notification-failure" {
		peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{4, 7, 0, 4}}}))
		err := <-finished
		joined = true
		if err == nil || s.akaPending != nil {
			t.Fatal("EAP failure retained pending identity")
		}
		assertNoPublication()
		return nil
	}
	idr := append([]byte{2, 0, 0, 0}, []byte(testIDrFQDN)...)
	peer.send(t, peer.protect(t, []akaWirePayload{{kind: 36, body: idr}, {kind: 48, body: []byte{3, 7, 0, 4}}}))
	initiator := peer.decrypt(t, peer.receive(t))
	authKey := independentHMACSHA256(msk, []byte("Key Pad for IKEv2"))
	signed := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
	signed = append(signed, independentHMACSHA256(peer.keys[160:192], idi)...)
	if len(initiator) != 1 || initiator[0].kind != 39 || !bytes.Equal(initiator[0].body[4:], independentHMACSHA256(authKey, signed)) {
		t.Fatal("initiator AUTH did not consume the independently derived MSK")
	}
	assertNoPublication()
	responder := independentResponderAUTH(msk, peer.keys[192:224], idr, peer.initResponse, peer.initiatorNonce)
	if mode == "bad-auth" {
		responder[0] ^= 1
	}
	child, err := testChildSA().Encode()
	if err != nil {
		t.Fatal(err)
	}
	peer.send(t, peer.protect(t, []akaWirePayload{
		{kind: 39, body: append([]byte{2, 0, 0, 0}, responder...)},
		{kind: 47, body: []byte{2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 10}},
		{kind: 33, body: child},
		{kind: 44, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 192, 0, 2, 10, 192, 0, 2, 10}},
		{kind: 45, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255}},
	}))
	if mode == "bad-auth" {
		err := <-finished
		joined = true
		if !errors.Is(err, ErrIKEAuthFailed) || s.akaPending != nil || s.ChildSAOut != nil {
			t.Fatal("bad responder AUTH published a new identity or Child SA")
		}
		assertNoPublication()
		return nil
	}
	var current *AKATemporaryIdentity
	select {
	case current = <-updates:
	case <-ctx.Done():
		t.Fatal("authenticated Connect failed to publish identity state")
	}
	cancel()
	err = <-finished
	joined = true
	if !errors.Is(err, context.Canceled) || s.ChildSAOut == nil || s.akaPending != nil {
		t.Fatal("Connect did not finish authentication and cleanup")
	}
	if current.ReauthID != nextID {
		t.Fatal("published wrong next identity or failed to retire missing next identity")
	}
	wantCounter := uint16(0)
	if fast && mode != "fallback" && nextID != "" {
		wantCounter = counter
	}
	if current.Counter != wantCounter {
		t.Fatal("cross-session counter lost the last-used boundary")
	}
	if nextID != "" && (!bytes.Equal(current.MK, mk) || !bytes.Equal(current.KAut, kAut) || !bytes.Equal(current.KEncr, kEncr)) {
		t.Fatal("stored transient keys do not match the authenticated derivation")
	}
	wantSIM := 1
	if fast && mode != "fallback" {
		wantSIM = 0
	}
	if provider.calls != wantSIM {
		t.Fatal("fast/full authentication used the wrong SIM path")
	}
	return current
}

func TestAKATemporaryIdentityConnectAcrossSessionsAndMissingNextRetirement(t *testing.T) {
	first := temporaryIdentityConnect(t, nil, "full", "first@public.invalid", 0)
	second := temporaryIdentityConnect(t, first, "fast", "second@public.invalid", 1)
	third := temporaryIdentityConnect(t, second, "fast", "", 2)
	if third.Pseudonym != "next-pseudonym" || len(third.MK) != 0 {
		t.Fatal("missing next must retire keys while retaining the full-auth pseudonym")
	}
	temporaryIdentityConnect(t, third, "full", "fresh@public.invalid", 0)
}

func TestAKATemporaryIdentityConnectFailureNeverPublishesReplacement(t *testing.T) {
	for _, mode := range []string{"eap-failure", "bad-auth", "cancel-before-auth", "notification-failure"} {
		t.Run(mode, func(t *testing.T) {
			temporaryIdentityConnect(t, syntheticTemporaryIdentity(), mode, "next@public.invalid", 21)
		})
	}
}

func TestAKATemporaryIdentityConnectTooSmallContinuesFullAuth(t *testing.T) {
	temporaryIdentityConnect(t, syntheticTemporaryIdentity(), "fallback", "full-next@public.invalid", 20)
}

func TestAKATemporaryIdentityConnectUsesAuthenticatedReverseKeyBranch(t *testing.T) {
	temporaryIdentityConnect(t, nil, "full-ckik", "reverse@public.invalid", 0)
}
