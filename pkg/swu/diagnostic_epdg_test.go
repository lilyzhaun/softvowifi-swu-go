package swu

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func TestDiagnosticEndpointTransportFactory(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		cfg := &Config{EpDGAddr: "epdg.example.invalid", EpDGPort: 4500}
		want := "epdg.example.invalid:4500"
		if pinned {
			cfg.DiagnosticRemoteIP = netip.MustParseAddr("192.0.2.1")
			want = "192.0.2.1:4500"
		}
		stop := errors.New("constructor stop")
		calls := 0
		cfg.TransportFactory = func(local, remote string) (Transport, error) {
			calls++
			if remote != want {
				t.Errorf("remote = %s, want %s", remote, want)
			}
			return nil, stop
		}
		sess := NewSession(cfg, zap.NewNop())
		err := sess.Connect(context.Background())
		sess.Shutdown()
		if err == nil || calls != 1 || cfg.EpDGAddr != "epdg.example.invalid" {
			t.Fatal("constructor did not stop or identity changed")
		}
	}
}

func TestDiagnosticEndpointUDPWithCookieNATDAndRedirect(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{EpDGAddr: "epdg.example.invalid", LocalAddr: "127.0.0.1", EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port)}
	cfg.DiagnosticRemoteIP = netip.MustParseAddr("127.0.0.1")
	calls := 0
	cfg.TransportFactory = func(local, remote string) (Transport, error) {
		calls++
		if remote != peer.LocalAddr().String() {
			t.Error("pin not used before resolution")
		}
		return ipsec.NewSocketManager(local, remote, "127.0.0.1:1")
	}
	sess := NewSession(cfg, zap.NewNop())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	finished := make(chan error, 1)
	t.Cleanup(func() { cancel(); <-finished; sess.Shutdown() })
	go func() { finished <- sess.Connect(ctx); close(finished) }()
	var firstSA []byte
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
		sa, _, notifies := decodeInitSA(t, buffer[:count])
		saBytes, err := sa.Encode()
		if err != nil {
			t.Fatal(err)
		}
		baseline := &ikev2.EncryptedPayloadSA{Proposals: ikev2.CreateIKEProposals("", nil)}
		wantSA, err := baseline.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(sa.Proposals) != 4 || !bytes.Equal(saBytes, wantSA) {
			t.Fatal("diagnostic changed four-suite offer")
		}
		if attempt == 0 {
			firstSA = saBytes
		} else if !bytes.Equal(firstSA, saBytes) {
			t.Fatal("COOKIE changed offers")
		}
		input := binary.BigEndian.AppendUint64(nil, packet.Header.SPIi)
		input = binary.BigEndian.AppendUint64(input, 0)
		input = append(input, 127, 0, 0, 1)
		input = binary.BigEndian.AppendUint16(input, cfg.EpDGPort)
		wantHash := sha1.Sum(input)
		sawNAT, sawCookie := false, false
		for _, notify := range notifies {
			switch notify.NotifyType {
			case ikev2.NAT_DETECTION_DESTINATION_IP:
				sawNAT = bytes.Equal(notify.NotifyData, wantHash[:])
			case ikev2.COOKIE:
				sawCookie = bytes.Equal(notify.NotifyData, []byte{1, 2, 3, 4})
			}
		}
		if !sawNAT || (attempt == 1 && !sawCookie) {
			t.Fatal("actual endpoint NAT-D or COOKIE differs")
		}
		response := ikev2.NewIKEPacket()
		response.Header = packet.Header
		response.Header.Flags = ikev2.FlagResponse
		notify := &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{1, 2, 3, 4}}
		if attempt == 1 {
			notify = &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.REDIRECT, NotifyData: []byte{ikev2.RedirectGWIPv4, 192, 0, 2, 9}}
		}
		response.Payloads = []ikev2.Payload{notify}
		raw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(raw, client); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-finished:
		if !errors.Is(err, ErrDiagnosticRedirect) || calls != 1 || cfg.EpDGAddr != "epdg.example.invalid" {
			t.Fatalf("pin redirect outcome: %v calls=%d", err, calls)
		}
	case <-ctx.Done():
		t.Fatal("redirect did not terminate")
	}
}

func TestDiagnosticRedirectDecision(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		cfg := &Config{EpDGAddr: "original.example.invalid"}
		if pinned {
			cfg.DiagnosticRemoteIP = netip.MustParseAddr("192.0.2.1")
		}
		err := cfg.acceptRedirect("192.0.2.9")
		if pinned {
			if !errors.Is(err, ErrDiagnosticRedirect) || cfg.EpDGAddr != "original.example.invalid" {
				t.Fatal("pin followed redirect")
			}
		} else if err != nil || cfg.EpDGAddr != "192.0.2.9" {
			t.Fatal("normal redirect changed")
		}
	}
}

func TestDiagnosticEndpointPreservesAUTHIdentityOverUDP(t *testing.T) {
	peer := newAKAWirePeer(t)
	cfg := &Config{
		EpDGAddr: "epdg.example.invalid", DiagnosticRemoteIP: netip.MustParseAddr("127.0.0.1"),
		EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), LocalAddr: "127.0.0.1",
		DNSServer: "127.0.0.1:1", APN: "ims", SIM: &vectorSIM{},
	}
	sess := NewSession(cfg, zap.NewNop())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	finished := make(chan error, 1)
	t.Cleanup(func() { cancel(); <-finished; sess.Shutdown() })
	go func() { finished <- sess.Connect(ctx); close(finished) }()
	peer.negotiate(t)
	assertAKAWireInitial(t, peer.decrypt(t, peer.receive(t)))
	peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{4, 0xa7, 0, 4}}}))
	select {
	case err := <-finished:
		if err == nil || err.Error() != "unexpected EAP Code: 4" || cfg.EpDGAddr != "epdg.example.invalid" {
			t.Fatalf("unexpected diagnostic terminal state: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("peer rejection did not terminate")
	}
}
