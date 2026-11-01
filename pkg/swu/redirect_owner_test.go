package swu

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestInitialRedirectCanReturnToCallerWithoutReusingSession(t *testing.T) {
	for _, policy := range []string{"caller", "default", "diagnostic"} {
		t.Run(policy, func(t *testing.T) {
			a := newAKAWirePeer(t)
			port := a.conn.LocalAddr().(*net.UDPAddr).Port
			b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { b.Close() })
			b.SetDeadline(time.Now().Add(3 * time.Second))
			s, provider := identitySession(t)
			cfg := s.cfg
			cfg.LocalAddr, cfg.EpDGAddr, cfg.EpDGPort = "127.0.0.1", "127.0.0.1", uint16(port)
			// Missing fields on the baseline compile, then fail through Connect.
			if policy != "default" {
				if err := json.Unmarshal([]byte(`{"ReturnInitialRedirect":true}`), cfg); err != nil {
					t.Fatal(err)
				}
			}
			if policy == "diagnostic" {
				cfg.DiagnosticRemoteIP = netip.MustParseAddr("127.0.0.1")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			done := make(chan error, 1)
			go func() { done <- s.Connect(ctx) }()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(4 * time.Second):
						t.Error("redirect connection did not stop")
					}
				}
				s.Shutdown()
			})
			raw := a.receive(t)
			request, err := ikev2.DecodePacket(raw)
			if err != nil {
				t.Fatal(err)
			}
			response := ikev2.NewIKEPacket()
			response.Header = &ikev2.IKEHeader{SPIi: request.Header.SPIi, SPIr: 4321, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
			response.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.REDIRECT, NotifyData: []byte{ikev2.RedirectGWIPv4, 127, 0, 0, 2}}}
			wire, err := response.Encode()
			if err != nil {
				t.Fatal(err)
			}
			a.send(t, wire)
			type reception struct {
				count int
				err   error
			}
			received := make(chan reception, 1)
			go func() {
				buffer := make([]byte, 4096)
				n, _, err := b.ReadFromUDP(buffer)
				received <- reception{n, err}
			}()
			select {
			case err := <-done:
				joined = true
				b.Close()
				packet := <-received
				if policy == "default" || packet.count != 0 {
					t.Fatal("redirect ownership policy changed default behavior or contacted the target")
				}
				if policy == "diagnostic" {
					if !errors.Is(err, ErrDiagnosticRedirect) {
						t.Fatal("fixed diagnostic endpoint lost redirect rejection")
					}
				} else {
					var redirect *RedirectError
					if !errors.As(err, &redirect) || redirect.NewAddr != "127.0.0.2" || cfg.EpDGAddr != "127.0.0.1" {
						t.Fatal("caller did not receive the target with original Config intact")
					}
				}
			case packet := <-received:
				if packet.err != nil || packet.count == 0 {
					t.Fatal("redirect neither returned nor reached its target")
				}
				if policy != "default" {
					t.Fatal("explicit caller-owned redirect reused the old Session")
				}
				cancel()
				<-done
				joined = true
			}
			if provider.calls != 0 || s.ChildSAIn != nil || s.ChildSAOut != nil {
				t.Fatal("initial redirect authenticated or installed a Child SA")
			}
			select {
			case <-s.done:
			default:
				t.Fatal("caller return preceded completed Connect cleanup")
			}
		})
	}
}
