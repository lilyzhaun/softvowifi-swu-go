package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

const testIDrFQDN = "epdg.example.test"

type postEAPSnap struct {
	childOut     bool
	authLifetime uint32
	mobike       bool
	ticket       []byte
	skd          []byte
	ticketCB     int
	idr          []byte
	msk          []byte
	msgBuffer    []byte
	redirected   bool
}

func testIDrPayload() *ikev2.EncryptedPayloadID {
	return &ikev2.EncryptedPayloadID{
		IDType:      ikev2.ID_FQDN,
		IDData:      []byte(testIDrFQDN),
		IsInitiator: false,
	}
}

func mustIDrBody(t *testing.T) []byte {
	t.Helper()
	body, err := testIDrPayload().Encode()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func newPostEAPSession(t *testing.T) (*Session, *int) {
	t.Helper()
	log, _ := debugDiagnosticLogger()
	ticketCB := 0
	sess := NewSession(&Config{
		SIM: issue25ReauthSIM{},
		OnTicketUpdate: func(_, _ []byte) {
			ticketCB++
		},
	}, log)
	enc, err := crypto.GetEncrypterWithKeyLen(12, 256)
	if err != nil {
		t.Fatal(err)
	}
	integ, err := crypto.GetIntegrityAlgorithm(12)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	mac := bytes.Repeat([]byte{7}, 32)
	sess.EncAlg, sess.IntegAlg = enc, integ
	sess.SPIr = 4321
	sess.PRFAlg = crypto.PRF_HMAC_SHA2_256
	sess.Keys = &ikev2.IKESAKeys{
		SK_ei: key,
		SK_er: bytes.Repeat([]byte{10}, 32),
		SK_ai: mac,
		SK_ar: bytes.Repeat([]byte{8}, 32),
		SK_d:  bytes.Repeat([]byte{5}, 32),
		SK_pi: bytes.Repeat([]byte{4}, 32),
		SK_pr: bytes.Repeat([]byte{3}, 32),
	}
	sess.MSK = []byte("0123456789abcdef0123456789abcdef")
	sess.ni = []byte("initiator-nonce-32-bytes-value!")
	sess.nr = []byte("responder-nonce-32-bytes-value!")
	sess.msgBuffer = []byte("real-message-1-sa-init-request")
	sess.saInitResp = []byte("real-message-2-sa-init-response")
	sess.peerIDrBody = mustIDrBody(t)
	sess.childSPI = 0x0a0b0c0d
	if _, err := sess.buildIKEAuthInitPayloads(); err != nil {
		t.Fatal(err)
	}
	return sess, &ticketCB
}

func independentHMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func independentResponderAUTH(msk, skPr, idrBody, realMessage2, ni []byte) []byte {
	authKey := independentHMACSHA256(msk, []byte("Key Pad for IKEv2"))
	idHash := independentHMACSHA256(skPr, idrBody)
	signed := make([]byte, 0, len(realMessage2)+len(ni)+len(idHash))
	signed = append(signed, realMessage2...)
	signed = append(signed, ni...)
	signed = append(signed, idHash...)
	return independentHMACSHA256(authKey, signed)
}

func validResponderAUTH(t *testing.T, sess *Session) *ikev2.EncryptedPayloadAuth {
	t.Helper()
	data := independentResponderAUTH(sess.MSK, sess.Keys.SK_pr, sess.peerIDrBody, sess.saInitResp, sess.ni)
	return &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: data}
}

func eapSuccessPayload() *ikev2.EncryptedPayloadEAP {
	return &ikev2.EncryptedPayloadEAP{
		EAPMessage: (&eap.EAPPacket{Code: eap.CodeSuccess, Identifier: 1}).Encode(),
	}
}

func testChildSA() *ikev2.EncryptedPayloadSA {
	spi := []byte{0x22, 0x22, 0x22, 0x22}
	prop := ikev2.NewProposal(1, ikev2.ProtoESP, spi)
	prop.AddTransform(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256)
	prop.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	return &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{prop}}
}

func mutationNotifies() []ikev2.Payload {
	lifetime := make([]byte, 4)
	binary.BigEndian.PutUint32(lifetime, 3600)
	return []ikev2.Payload{
		&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: lifetime},
		&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED},
		&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.TICKET_OPAQUE, NotifyData: []byte("ticket-bytes")},
		&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.REDIRECT, NotifyData: []byte{ikev2.RedirectGWIPv4, 192, 0, 2, 9}},
	}
}

func wrapAuth(t *testing.T, sess *Session, payloads []ikev2.Payload) []byte {
	t.Helper()
	return encodePeerPacket(t, sess, payloads, ikev2.IKE_AUTH, sess.NextSequenceNumber(), true)
}

func snapPostEAP(s *Session, ticketCB int) postEAPSnap {
	return postEAPSnap{
		childOut:     s.ChildSAOut != nil,
		authLifetime: s.authLifetime,
		mobike:       s.mobikeSupported,
		ticket:       bytes.Clone(s.resumeTicket),
		skd:          bytes.Clone(s.resumeOldSKd),
		ticketCB:     ticketCB,
		idr:          bytes.Clone(s.peerIDrBody),
		msk:          bytes.Clone(s.MSK),
		msgBuffer:    bytes.Clone(s.msgBuffer),
	}
}

func assertSnapUnchanged(t *testing.T, before, after postEAPSnap) {
	t.Helper()
	if before.childOut != after.childOut || before.authLifetime != after.authLifetime || before.mobike != after.mobike {
		t.Fatalf("SA/notify state mutated: before=%+v after=%+v", before, after)
	}
	if !bytes.Equal(before.ticket, after.ticket) || !bytes.Equal(before.skd, after.skd) || before.ticketCB != after.ticketCB {
		t.Fatalf("ticket state mutated: before=%+v after=%+v", before, after)
	}
	if !bytes.Equal(before.idr, after.idr) || !bytes.Equal(before.msk, after.msk) || !bytes.Equal(before.msgBuffer, after.msgBuffer) {
		t.Fatalf("transcript state mutated: before=%+v after=%+v", before, after)
	}
}

func authReason(err error) string {
	var fail *IKEAuthFailure
	if errors.As(err, &fail) {
		return fail.Reason
	}
	return ""
}

func Test_handleIKEAuthFinalResp_commitsChildSA_whenPostEAPSharedKeyAUTHValid(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	payloads := []ikev2.Payload{testIDrPayload(), validResponderAUTH(t, sess), testChildSA()}
	payloads = append(payloads, mutationNotifies()[:3]...)
	raw := wrapAuth(t, sess, payloads)

	err := sess.handleIKEAuthFinalResp(raw)
	if err != nil {
		t.Fatalf("valid AUTH+ChildSA: %v", err)
	}
	if sess.ChildSAOut == nil {
		t.Fatal("Child SA was not committed")
	}
	if sess.authLifetime != 3600 || !sess.mobikeSupported || len(sess.resumeTicket) == 0 {
		t.Fatalf("authenticated notifies not applied: lifetime=%d mobike=%v ticket=%d", sess.authLifetime, sess.mobikeSupported, len(sess.resumeTicket))
	}
	if *ticketCB != 1 {
		t.Fatalf("OnTicketUpdate calls=%d", *ticketCB)
	}
	if !bytes.Equal(sess.msgBuffer, []byte("real-message-1-sa-init-request")) {
		t.Fatal("msgBuffer was overwritten")
	}
}

func Test_handleIKEAuthFinalResp_rejects_whenAUTHMissingWithChildSA(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	payloads := append([]ikev2.Payload{testIDrPayload(), testChildSA()}, mutationNotifies()...)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, payloads))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "missing" {
		t.Fatalf("got %v", err)
	}
	if _, ok := err.(*RedirectError); ok {
		t.Fatal("redirect applied before AUTH")
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenAUTHZero(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	zero := &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: make([]byte, 32)}
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), zero, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "zero" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenAUTHMethodWrong(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	auth := validResponderAUTH(t, sess)
	auth.AuthMethod = ikev2.AuthMethodRSASig
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "method" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenAUTHDuplicated(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	auth := validResponderAUTH(t, sess)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "multiple" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenAUTHTampered(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	auth := validResponderAUTH(t, sess)
	auth.AuthData = bytes.Clone(auth.AuthData)
	auth.AuthData[0] ^= 0xff
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "mismatch" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenMSKAbsent(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.MSK = nil
	before := snapPostEAP(sess, *ticketCB)
	auth := &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: bytes.Repeat([]byte{1}, 32)}
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "msk" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenMSKZero(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.MSK = make([]byte, 32)
	before := snapPostEAP(sess, *ticketCB)
	auth := &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey, AuthData: bytes.Repeat([]byte{1}, 32)}
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "msk" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejectsReplay_whenSAInitTranscriptDiffers(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	auth := validResponderAUTH(t, sess)
	sess.saInitResp = []byte("different-sa-init-response")
	before := snapPostEAP(sess, *ticketCB)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "mismatch" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejectsReplay_whenNonceDiffers(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	auth := validResponderAUTH(t, sess)
	sess.ni = []byte("other-initiator-nonce-32bytes!!")
	before := snapPostEAP(sess, *ticketCB)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "mismatch" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_rejects_whenIDrConflicts(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	auth := validResponderAUTH(t, sess)
	other := &ikev2.EncryptedPayloadID{IDType: ikev2.ID_FQDN, IDData: []byte("other.example.test"), IsInitiator: false}
	before := snapPostEAP(sess, *ticketCB)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{other, auth, testChildSA()}))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "idr" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_handleIKEAuthFinalResp_needInitiatorAUTH_whenSuccessHasNoChildSA(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}))
	if !errors.Is(err, errIKEAuthNeedInitiatorAUTH) {
		t.Fatalf("got %v", err)
	}
	after := snapPostEAP(sess, *ticketCB)
	if after.childOut || after.ticketCB != before.ticketCB || after.authLifetime != 0 {
		t.Fatalf("Success without SA committed state: %+v", after)
	}
}

func assertInitiatorAUTHSent(t *testing.T, payloads []ikev2.Payload) {
	t.Helper()
	if len(payloads) != 1 {
		t.Fatalf("initiator AUTH payloads=%d", len(payloads))
	}
	auth, ok := payloads[0].(*ikev2.EncryptedPayloadAuth)
	if !ok || auth.AuthMethod != ikev2.AuthMethodSharedKey || len(auth.AuthData) == 0 {
		t.Fatal("initiator AUTH not sent")
	}
}

func Test_completePostEAP_sendsInitiatorAUTH_whenSuccessHasNoChildSA(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	first := wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()})
	sent := 0
	err := sess.completePostEAP(first, func(payloads []ikev2.Payload) ([]byte, error) {
		sent++
		assertInitiatorAUTHSent(t, payloads)
		assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
		return wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), validResponderAUTH(t, sess), testChildSA()}), nil
	})
	if err != nil {
		t.Fatalf("completePostEAP: %v", err)
	}
	if sent != 1 {
		t.Fatalf("sendFinal calls=%d", sent)
	}
	if sess.ChildSAOut == nil {
		t.Fatal("final AUTH+ChildSA not committed")
	}
}

func Test_completePostEAP_sendsOnce_whenSuccessPiggybacksSAAndAUTH(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	piggy := []ikev2.Payload{testIDrPayload(), eapSuccessPayload(), validResponderAUTH(t, sess), testChildSA()}
	piggy = append(piggy, mutationNotifies()...)
	sent := 0
	err := sess.completePostEAP(wrapAuth(t, sess, piggy), func(payloads []ikev2.Payload) ([]byte, error) {
		sent++
		assertInitiatorAUTHSent(t, payloads)
		assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
		return wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), validResponderAUTH(t, sess), testChildSA()}), nil
	})
	if err != nil {
		t.Fatalf("completePostEAP piggyback: %v", err)
	}
	if sent != 1 {
		t.Fatalf("sendFinal calls=%d", sent)
	}
	if sess.ChildSAOut == nil {
		t.Fatal("correct final reply did not commit")
	}
}

func Test_completePostEAP_ignoresPiggybackSAWithoutAUTH_andSendsInitiatorAUTH(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	payloads := append([]ikev2.Payload{testIDrPayload(), eapSuccessPayload(), testChildSA()}, mutationNotifies()...)
	sent := 0
	err := sess.completePostEAP(wrapAuth(t, sess, payloads), func(auth []ikev2.Payload) ([]byte, error) {
		sent++
		assertInitiatorAUTHSent(t, auth)
		assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
		return wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), validResponderAUTH(t, sess), testChildSA()}), nil
	})
	if err != nil {
		t.Fatalf("completePostEAP: %v", err)
	}
	if sent != 1 {
		t.Fatalf("sendFinal calls=%d", sent)
	}
	if sess.ChildSAOut == nil {
		t.Fatal("final reply not committed")
	}
}

func Test_completePostEAP_rejects_whenFinalAUTHMissing(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	err := sess.completePostEAP(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}), func(payloads []ikev2.Payload) ([]byte, error) {
		assertInitiatorAUTHSent(t, payloads)
		return wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), testChildSA()}), nil
	})
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "missing" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_completePostEAP_rejects_whenFinalAUTHWrong(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	err := sess.completePostEAP(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}), func(payloads []ikev2.Payload) ([]byte, error) {
		assertInitiatorAUTHSent(t, payloads)
		auth := validResponderAUTH(t, sess)
		auth.AuthData = bytes.Clone(auth.AuthData)
		auth.AuthData[0] ^= 0xff
		return wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), auth, testChildSA()}), nil
	})
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "mismatch" {
		t.Fatalf("got %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_completePostEAP_doesNotSend_whenErrorNotify(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	before := snapPostEAP(sess, *ticketCB)
	sent := 0
	err := sess.completePostEAP(wrapAuth(t, sess, []ikev2.Payload{
		testIDrPayload(),
		eapSuccessPayload(),
		&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTHENTICATION_FAILED},
	}), func([]ikev2.Payload) ([]byte, error) {
		sent++
		return nil, errors.New("must not send")
	})
	var rej *RejectError
	if !errors.As(err, &rej) || rej.NotifyType != ikev2.AUTHENTICATION_FAILED || sent != 0 {
		t.Fatalf("err=%v sent=%d", err, sent)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_completePostEAP_doesNotSend_whenSuccessHasNoMSK(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.MSK = nil
	before := snapPostEAP(sess, *ticketCB)
	sent := 0
	err := sess.completePostEAP(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}), func([]ikev2.Payload) ([]byte, error) {
		sent++
		return nil, errors.New("must not send")
	})
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "msk" || sent != 0 {
		t.Fatalf("err=%v sent=%d", err, sent)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_completePostEAP_doesNotSend_whenMSKAllZero(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.MSK = make([]byte, 32)
	before := snapPostEAP(sess, *ticketCB)
	sent := 0
	err := sess.completePostEAP(wrapAuth(t, sess, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}), func([]ikev2.Payload) ([]byte, error) {
		sent++
		return nil, errors.New("must not send")
	})
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "msk" || sent != 0 {
		t.Fatalf("err=%v sent=%d", err, sent)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_processIKEAuthEAPRound_continues_whenAUTH1HasIDrAndEAPWithoutAUTH(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.peerIDrBody = nil
	before := snapPostEAP(sess, *ticketCB)
	req := (&eap.EAPPacket{Code: eap.CodeRequest, Identifier: 7, Type: eap.TypeIdentity}).Encode()
	send, eapDone, err := sess.processIKEAuthEAPRound([]ikev2.Payload{
		testIDrPayload(),
		&ikev2.EncryptedPayloadEAP{EAPMessage: req},
	})
	if err != nil || eapDone || send == nil {
		t.Fatalf("err=%v done=%v send=%v", err, eapDone, send)
	}
	if !bytes.Equal(sess.peerIDrBody, mustIDrBody(t)) {
		t.Fatal("AUTH1 IDr was not captured")
	}
	if sess.ChildSAOut != nil || *ticketCB != before.ticketCB {
		t.Fatal("AUTH1 mutated Child SA")
	}
}

func Test_processIKEAuthEAPRound_eapDone_whenSuccessWithoutAUTH(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	success := (&eap.EAPPacket{Code: eap.CodeSuccess, Identifier: 1}).Encode()
	send, eapDone, err := sess.processIKEAuthEAPRound([]ikev2.Payload{
		testIDrPayload(),
		&ikev2.EncryptedPayloadEAP{EAPMessage: success},
	})
	if err != nil || send != nil || !eapDone {
		t.Fatalf("err=%v send=%v done=%v", err, send, eapDone)
	}
	if sess.ChildSAOut != nil {
		t.Fatal("EAP Success committed Child SA")
	}
}

func Test_handleIKEAuthFinalResp_resumeFailClosed_doesNotUseMSKVerifier(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.resumeAuthPending = true
	before := snapPostEAP(sess, *ticketCB)
	payloads := append([]ikev2.Payload{testIDrPayload(), validResponderAUTH(t, sess), testChildSA()}, mutationNotifies()...)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, payloads))
	if !errors.Is(err, ErrResumeAuthUnsupported) {
		t.Fatalf("got %v", err)
	}
	if errors.Is(err, ErrIKEAuthFailed) {
		t.Fatal("MSK verifier applied to resume")
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func Test_performSessionResumption_failClosed_beforeSideEffects(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.resumeTicket = []byte("opaque-ticket")
	sess.resumeOldSKd = bytes.Repeat([]byte{9}, 32)
	before := snapPostEAP(sess, *ticketCB)
	err := sess.performSessionResumption()
	if !errors.Is(err, ErrResumeAuthUnsupported) {
		t.Fatalf("got %v", err)
	}
	after := snapPostEAP(sess, *ticketCB)
	if after.childOut || after.ticketCB != before.ticketCB {
		t.Fatal("resume applied Child SA or ticket callback")
	}
	if sess.ChildSAOut != nil {
		t.Fatal("resume committed Child SA")
	}
}

func Test_resetIKEAuthTranscripts_clearsIDrAndRealMessage2(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	sess.resumeAuthPending = true
	sess.resetIKEAuthTranscripts()
	if sess.saInitResp != nil || sess.peerIDrBody != nil || sess.localIDiBody != nil || sess.resumeAuthPending {
		t.Fatal("transcripts not cleared")
	}
	if !bytes.Equal(sess.msgBuffer, []byte("real-message-1-sa-init-request")) {
		t.Fatal("msgBuffer must be preserved by transcript reset")
	}
}

func Test_handleIKEAuthFinalResp_usesFinalIDrBody_whenPreviouslyUnset(t *testing.T) {
	sess, _ := newPostEAPSession(t)
	sess.peerIDrBody = nil
	idr := testIDrPayload()
	body, err := idr.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sess.peerIDrBody = body
	auth := validResponderAUTH(t, sess)
	sess.peerIDrBody = nil
	err = sess.handleIKEAuthFinalResp(wrapAuth(t, sess, []ikev2.Payload{idr, auth, testChildSA()}))
	if err != nil {
		t.Fatalf("bind actual IDr: %v", err)
	}
	if !bytes.Equal(sess.peerIDrBody, body) {
		t.Fatal("final IDr body not committed")
	}
	if sess.ChildSAOut == nil {
		t.Fatal("Child SA missing after binding IDr from peer")
	}
}
