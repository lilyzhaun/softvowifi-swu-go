package swu

import (
	"bytes"
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func assertInnerFamilyRequest(t *testing.T, family string, payloads []ikev2.Payload) {
	t.Helper()
	var cp *ikev2.EncryptedPayloadCP
	var selectors []*ikev2.EncryptedPayloadTS
	for _, payload := range payloads {
		switch p := payload.(type) {
		case *ikev2.EncryptedPayloadCP:
			if cp != nil {
				t.Fatal("duplicate CP request")
			}
			cp = p
		case *ikev2.EncryptedPayloadTS:
			selectors = append(selectors, p)
		}
	}
	if cp == nil || cp.CFGType != ikev2.CFG_REQUEST || len(selectors) != 2 || !selectors[0].IsInitiator || selectors[1].IsInitiator {
		t.Fatal("missing initial CP/TS request")
	}
	var wantAttributes []uint16
	var wantFamilies []uint8
	if family != "ipv6" {
		wantAttributes = append(wantAttributes, ikev2.INTERNAL_IP4_ADDRESS, ikev2.INTERNAL_IP4_DNS, ikev2.P_CSCF_IP4_ADDRESS)
		wantFamilies = append(wantFamilies, ikev2.TS_IPV4_ADDR_RANGE)
	}
	if family != "ipv4" {
		wantAttributes = append(wantAttributes, ikev2.INTERNAL_IP6_ADDRESS, ikev2.INTERNAL_IP6_DNS, ikev2.P_CSCF_IP6_ADDRESS, ikev2.ASSIGNED_PCSCF_IP6_ADDRESS)
		wantFamilies = append(wantFamilies, ikev2.TS_IPV6_ADDR_RANGE)
	}
	var attributes []uint16
	for _, attribute := range cp.Attributes {
		attributes = append(attributes, attribute.Type)
		if len(attribute.Value) != 0 {
			t.Error("request manufactured an assigned address")
		}
	}
	if !slices.Equal(attributes, wantAttributes) {
		t.Errorf("actual CP families: got=%v want=%v", attributes, wantAttributes)
	}
	for _, ts := range selectors {
		var families []uint8
		for _, selector := range ts.TrafficSelectors {
			families = append(families, uint8(selector.TSType))
			if selector.IPProtocol != 0 || selector.StartPort != 0 || selector.EndPort != 65535 || !bytes.Equal(selector.StartAddr, make([]byte, len(selector.StartAddr))) || !bytes.Equal(selector.EndAddr, bytes.Repeat([]byte{255}, len(selector.EndAddr))) {
				t.Error("initial selector no longer requests the original full range")
			}
		}
		if !slices.Equal(families, wantFamilies) {
			t.Errorf("actual TS families: got=%v want=%v", families, wantFamilies)
		}
	}
}

func TestInnerAddressFamilyRequestSnapshot(t *testing.T) {
	var legacy []byte
	for _, family := range []string{"", "dual-stack", "ipv4", "ipv6"} {
		t.Run("family="+family, func(t *testing.T) {
			s, _ := newPostEAPSession(t, func(c *Config) {
				c.InnerAddressFamily, c.APN, c.TUNMTU = family, "voice.example.test", 1340
				c.RemoteAddressFamily = ipsec.AddressFamilyIPv4Only
			})
			request, err := ikev2.DecodePacket(s.initialChildRequest)
			if err != nil {
				t.Fatal(err)
			}
			assertInnerFamilyRequest(t, family, request.Payloads)
			if family == "" {
				legacy = bytes.Clone(s.initialChildRequest)
			} else if family == "dual-stack" && !bytes.Equal(legacy, s.initialChildRequest) {
				t.Fatal("explicit dual-stack changed legacy CP/SA/TS bytes")
			}
			captured := bytes.Clone(s.initialChildRequest)
			s.cfg.InnerAddressFamily = "invalid-later-edit"
			payloads, err := s.buildIKEAuthInitPayloads()
			if err != nil {
				t.Fatal(err)
			}
			assertInnerFamilyRequest(t, family, payloads)
			if !bytes.Equal(captured, s.initialChildRequest) || s.interfaceMTU != 1340 || s.cfg.APN != "voice.example.test" || s.remoteAddressFamily != ipsec.AddressFamilyIPv4Only {
				t.Fatal("later caller edit changed captured request or independent APN/MTU/outer family")
			}
		})
	}
}

func TestInnerAddressFamilyProtectedAUTH(t *testing.T) {
	for _, family := range []string{"", "dual-stack", "ipv4", "ipv6"} {
		t.Run("family="+family, func(t *testing.T) {
			peer := newAKAWirePeer(t)
			previous, provider := identitySession(t)
			cfg := previous.cfg
			cfg.LocalAddr, cfg.EpDGAddr, cfg.APN = "127.0.0.1", "127.0.0.1", "voice.example.test"
			cfg.EpDGPort = uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)
			cfg.InnerAddressFamily, cfg.TUNMTU = family, 1340
			cfg.RemoteAddressFamily = ipsec.AddressFamilyIPv4Only
			s := NewSession(cfg, zap.NewNop())
			cfg.InnerAddressFamily = "invalid-later-edit"
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			done := make(chan struct{})
			var connectErr error
			go func() { connectErr = s.Connect(ctx); close(done) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
					s.Shutdown()
				case <-time.After(3 * time.Second):
					t.Error("inner-family Connect did not retire")
				}
			})
			peer.negotiate(t)
			wire := peer.decrypt(t, peer.receive(t))
			var payloads []ikev2.Payload
			for _, p := range wire {
				switch ikev2.PayloadType(p.kind) {
				case ikev2.CP:
					cp, err := ikev2.DecodePayloadCP(p.body)
					if err != nil {
						t.Fatal(err)
					}
					payloads = append(payloads, cp)
				case ikev2.TSI, ikev2.TSR:
					ts, err := ikev2.DecodePayloadTS(p.body, ikev2.PayloadType(p.kind) == ikev2.TSI)
					if err != nil {
						t.Fatal(err)
					}
					payloads = append(payloads, ts)
				case ikev2.IDr:
					id, err := ikev2.DecodePayloadID(p.body, false)
					if err != nil || string(id.IDData) != "voice.example.test" {
						t.Fatal("independent requested APN changed")
					}
				}
			}
			assertInnerFamilyRequest(t, family, payloads)
			cancel()
			<-done
			if connectErr == nil || provider.calls != 0 || s.ChildSAIn != nil || s.ChildSAOut != nil || s.interfaceMTU != 1340 {
				t.Fatal("AUTH1 was advertised as established or changed independent MTU")
			}
		})
	}
}
