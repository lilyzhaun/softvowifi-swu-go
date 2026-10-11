package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"
)

func independentNotifyBody(notifyType uint16, data []byte) []byte {
	body := []byte{1, 0}
	body = binary.BigEndian.AppendUint16(body, notifyType)
	return append(body, data...)
}

func Test_IKEAuthMetadata_whenUDPPeerSendsNotifyBesideChallenge(t *testing.T) {
	peer := newAKAWirePeer(t)
	provider := &akaWireSIM{vectorSIM: vectorSIM{
		res: bytes.Repeat([]byte{0x61}, 8), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16),
	}}
	keys := referenceAKAKeys(&provider.vectorSIM, false)
	challenge := referenceChallenge(keys[16:32], false)
	secret := []byte(notifySecret)
	log, output := diagnosticLogger()
	sess := NewSession(&Config{
		LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1",
		EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), APN: "ims", SIM: provider,
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
	assertAKAWireInitial(t, peer.decrypt(t, peer.receive(t)))
	peer.send(t, peer.protect(t, []akaWirePayload{
		{kind: 36, body: append([]byte{2, 0, 0, 0}, []byte("epdg.example.invalid")...)},
		{kind: 48, body: challenge},
		{kind: 41, body: independentNotifyBody(41101, secret)},
		{kind: 41, body: independentNotifyBody(16432, nil)},
	}))
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("Connect did not reject malformed/duplicate equipment request")
	}
	if connectErr == nil || connectErr.Error() != "invalid DEVICE_IDENTITY request" || provider.calls != 0 {
		t.Fatal("malformed equipment request was not rejected before SIM")
	}
	if err := peer.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := peer.conn.ReadFromUDP(make([]byte, 4096))
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatal("invalid equipment request produced a UDP response")
	}
	events := authMetadataEvents(t, output)
	if len(events) == 0 {
		t.Fatal("missing IKE_AUTH metadata")
	}
	first := events[0]
	if first.Direction != "received" || first.Phase != "eap_loop" || !first.ProtectedPacketDecoded {
		t.Fatalf("incorrect AUTH1 metadata labels: %+v", first)
	}
	if !reflect.DeepEqual(first.ParsedPayloadTypes, []int{36, 48, 41, 41}) || first.ParsedPayloadCount != 4 || first.ParsedPayloadTruncated {
		t.Fatalf("AUTH1 payload types lost Notify beside EAP: %+v", first)
	}
	if first.NotificationCount != 2 || first.NotificationsTruncated || len(first.Notifications) != 2 {
		t.Fatalf("notify records missing: %+v", first.Notifications)
	}
	if first.Notifications[0].Type != 41101 || first.Notifications[0].Protocol != 1 || first.Notifications[0].SPILength != 0 || first.Notifications[0].DataLength != len(secret) {
		t.Fatalf("41101 request metadata incorrect: %+v", first.Notifications[0])
	}
	if first.Notifications[1].Type != 16432 || first.Notifications[1].DataLength != 0 {
		t.Fatalf("16432 numeric metadata incorrect: %+v", first.Notifications[1])
	}
	assertAuthMetadataWhitelist(t, output)
	assertDiagnosticPrivacy(t, output, secret, []byte(idSecret), provider.res, provider.ck, provider.ik)
}
