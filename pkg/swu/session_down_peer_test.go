package swu

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func Test_PeerInformational_attemptsReplyBeforeBlockedObserver(t *testing.T) {
	cases := []struct {
		name   string
		pkt    func(*testing.T, *Session) []byte
		reason SessionDownReason
	}{
		{"ike_delete", encodePeerIKEDelete, SessionDownPeerIKEDelete},
		{"redirect", encodePeerRedirect, SessionDownRedirect},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, pipe := newPeerInformationalSession(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			var got SessionDownReason
			sess.OnClosedReason = func(reason SessionDownReason) {
				got = reason
				close(entered)
				<-release
			}

			pipe.ike <- tc.pkt(t, sess)

			select {
			case <-pipe.sent:
			case <-time.After(2 * time.Second):
				t.Fatal("INFORMATIONAL reply not attempted while observer blocked")
			}
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("observer not invoked after reply attempt")
			}
			if got != tc.reason {
				t.Fatalf("reason=%s want %s", got, tc.reason)
			}
			close(release)
		})
	}
}

func Test_PeerInformational_observesAfterFailedReplyAttempt(t *testing.T) {
	sess, pipe := newPeerInformationalSession(t)
	pipe.sendErr = errSendIKE
	entered := make(chan struct{})
	sess.OnClosedReason = func(SessionDownReason) { close(entered) }

	pipe.ike <- encodePeerIKEDelete(t, sess)

	select {
	case <-pipe.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("failed reply attempt not reached")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("closed reason not observed after failed reply")
	}
}

func Test_PeerIKEDelete_skipCancel_whenLegacyOnSessionDown(t *testing.T) {
	sess, pipe := newPeerInformationalSession(t)
	sess.OnSessionDown = func() {}
	done := make(chan struct{})
	sess.OnClosedReason = func(SessionDownReason) { close(done) }
	pipe.ike <- encodePeerIKEDelete(t, sess)
	select {
	case <-pipe.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("reply not attempted")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reason not observed")
	}
	if sess.ctx.Err() != nil {
		t.Fatalf("legacy skip-cancel broken: %v", sess.ctx.Err())
	}
}

type pipeTransport struct {
	ike     chan []byte
	sent    chan []byte
	sendErr error
}

var errSendIKE = errPipeSend{}

type errPipeSend struct{}

func (errPipeSend) Error() string { return "send ike failed" }

func (p *pipeTransport) Start() {}
func (p *pipeTransport) Stop()  {}
func (p *pipeTransport) SendIKE(b []byte) error {
	p.sent <- append([]byte(nil), b...)
	return p.sendErr
}
func (p *pipeTransport) SendESP([]byte) error                 { return nil }
func (p *pipeTransport) IKEPackets() <-chan []byte            { return p.ike }
func (p *pipeTransport) ESPPackets() <-chan []byte            { return nil }
func (p *pipeTransport) NetEventsChan() <-chan ipsec.NetEvent { return nil }

func newPeerInformationalSession(t *testing.T) (*Session, *pipeTransport) {
	t.Helper()
	sess := newClosedTestSession(t)
	enc, err := crypto.GetEncrypterWithKeyLen(uint16(ikev2.ENCR_AES_CBC), 128)
	if err != nil {
		t.Fatalf("encrypter: %v", err)
	}
	integ, err := crypto.GetIntegrityAlgorithm(uint16(ikev2.AUTH_HMAC_SHA2_256_128))
	if err != nil {
		t.Fatal(err)
	}
	sess.SPIr = 4321
	sess.EncAlg = enc
	sess.IntegAlg = integ
	sess.Keys = &ikev2.IKESAKeys{
		SK_ei: bytes.Repeat([]byte{1}, enc.KeySize()), SK_er: bytes.Repeat([]byte{2}, enc.KeySize()),
		SK_ai: bytes.Repeat([]byte{3}, integ.KeySize()), SK_ar: bytes.Repeat([]byte{4}, integ.KeySize()),
	}
	pipe := &pipeTransport{
		ike:  make(chan []byte, 1),
		sent: make(chan []byte, 1),
	}
	sess.socket = pipe
	sess.startIKEControlLoop()
	t.Cleanup(func() { close(pipe.ike) })
	return sess, pipe
}

func encodePeerIKEDelete(t *testing.T, sess *Session) []byte {
	t.Helper()
	return encodeInformational(t, sess, &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoIKE})
}

func encodePeerRedirect(t *testing.T, sess *Session) []byte {
	t.Helper()
	data := append([]byte{ikev2.RedirectGWIPv4}, net.IPv4(192, 0, 2, 1).To4()...)
	return encodeInformational(t, sess, &ikev2.EncryptedPayloadNotify{
		NotifyType: ikev2.REDIRECT,
		NotifyData: data,
	})
}

func encodeInformational(t *testing.T, sess *Session, payload ikev2.Payload) []byte {
	t.Helper()
	return encodePeerPacket(t, sess, []ikev2.Payload{payload}, ikev2.INFORMATIONAL, 7, false)
}
