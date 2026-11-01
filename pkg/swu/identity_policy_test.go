package swu

import (
	"bytes"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestIdentityPolicyInvalidInputStopsBeforeTransport(t *testing.T) {
	policies := []IdentityPolicy{
		{},
		{LocalIDType: ikev2.ID_FQDN, RequestedIDrType: ikev2.ID_FQDN},
		{LocalIDType: ikev2.ID_RFC822_ADDR, RequestedIDrType: ikev2.ID_RFC822_ADDR},
		{LocalIDType: 255, RequestedIDrType: ikev2.ID_FQDN},
	}
	for _, peer := range []PeerIdentity{
		{Type: ikev2.ID_FQDN}, {Type: ikev2.ID_FQDN, Data: []byte("*.example.test")},
		{Type: ikev2.ID_FQDN, Data: []byte("bad\x00.example.test")},
		{Type: ikev2.ID_RFC822_ADDR, Data: []byte("missing-realm")},
		{Type: ikev2.ID_RFC822_ADDR, Data: []byte("@example.test")},
		{Type: ikev2.ID_IPV4_ADDR, Data: make([]byte, 16)},
		{Type: ikev2.ID_IPV6_ADDR, Data: make([]byte, 4)},
		{Type: ikev2.ID_KEY_ID, Data: make([]byte, 1025)},
		{Type: ikev2.ID_DER_ASN1_DN, Data: []byte("unsupported")},
	} {
		policies = append(policies, IdentityPolicy{LocalIDType: ikev2.ID_RFC822_ADDR, RequestedIDrType: ikev2.ID_FQDN, Peer: &peer})
	}
	for _, policy := range policies {
		transportCalls := 0
		cfg := &Config{IdentityPolicy: &policy, TransportFactory: func(string, string) (Transport, error) {
			transportCalls++
			return nil, errors.New("unexpected transport")
		}}
		if !errors.Is(cfg.ValidateIdentityPolicy(), ErrInvalidIdentityPolicy) {
			t.Fatal("invalid explicit identity policy passed validation")
		}
		session := NewSession(cfg, zap.NewNop())
		cfg.IdentityPolicy = nil
		err := session.Connect(t.Context())
		if !errors.Is(err, ErrInvalidIdentityPolicy) || transportCalls != 0 {
			t.Fatalf("invalid captured policy fell back or opened transport: %v", err)
		}
	}
}

func TestIdentityPolicyCapturesTypesAndPeerBytes(t *testing.T) {
	policy := &IdentityPolicy{LocalIDType: ikev2.ID_KEY_ID, RequestedIDrType: ikev2.ID_KEY_ID,
		Peer: &PeerIdentity{Type: ikev2.ID_FQDN, Data: []byte(testIDrFQDN)}}
	session, _ := newPostEAPSession(t, func(cfg *Config) { cfg.IdentityPolicy, cfg.APN = policy, "ims" })
	policy.LocalIDType, policy.RequestedIDrType = ikev2.ID_RFC822_ADDR, ikev2.ID_FQDN
	policy.Peer.Data[0] = 'x'
	session.cfg.IdentityPolicy = nil
	payloads, err := session.buildIKEAuthInitPayloads()
	if err != nil || payloads[0].(*ikev2.EncryptedPayloadID).IDType != ikev2.ID_KEY_ID || payloads[1].(*ikev2.EncryptedPayloadID).IDType != ikev2.ID_KEY_ID {
		t.Fatalf("caller mutation changed captured outgoing types: %v", err)
	}
	if err := session.captureEAPIDr([]ikev2.Payload{testIDrPayload()}); err != nil {
		t.Fatalf("caller mutation changed captured peer constraint: %v", err)
	}
}

func TestIdentityPolicyFinalPeerConstraintKeepsRawAUTH(t *testing.T) {
	for _, scenario := range []string{"match", "different-type", "different-data"} {
		t.Run(scenario, func(t *testing.T) {
			session, callback := newPostEAPSession(t, func(cfg *Config) {
				cfg.APN = "ims"
				cfg.IdentityPolicy = &IdentityPolicy{LocalIDType: ikev2.ID_RFC822_ADDR, RequestedIDrType: ikev2.ID_FQDN,
					Peer: &PeerIdentity{Type: ikev2.ID_FQDN, Data: []byte(testIDrFQDN)}}
			})
			session.peerIDrBody = nil
			body := append([]byte{ikev2.ID_FQDN, 0x91, 0x42, 0xf3}, []byte(testIDrFQDN)...)
			if scenario == "different-type" {
				body[0] = ikev2.ID_KEY_ID
			} else if scenario == "different-data" {
				body[4] = 'x'
			}
			auth := &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey,
				AuthData: independentResponderAUTH(session.MSK, session.Keys.SK_pr, body, session.saInitResp, session.ni)}
			before := snapPostEAP(session, *callback)
			err := session.handleIKEAuthFinalResp(wrapAuth(t, session, []ikev2.Payload{wireIDrBody(body), auth, testChildSA()}))
			if scenario == "match" {
				if err != nil || session.ChildSAOut == nil || !bytes.Equal(session.peerIDrBody, body) {
					t.Fatalf("matching constraint lost raw AUTH or Child commit: %v", err)
				}
			} else {
				if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "peer_identity" {
					t.Fatalf("peer constraint did not reject before commit: %v", err)
				}
				assertSnapUnchanged(t, before, snapPostEAP(session, *callback))
			}
		})
	}
}

func TestIdentityPolicyPeerFormsAndNilCompatibility(t *testing.T) {
	for _, peer := range []PeerIdentity{
		{Type: ikev2.ID_FQDN, Data: []byte("epdg.example.test")},
		{Type: ikev2.ID_RFC822_ADDR, Data: []byte("peer@example.test")},
		{Type: ikev2.ID_KEY_ID, Data: []byte{0, 0xff, 1}},
		{Type: ikev2.ID_IPV4_ADDR, Data: []byte{192, 0, 2, 1}},
		{Type: ikev2.ID_IPV6_ADDR, Data: make([]byte, 16)},
	} {
		cfg := &Config{IdentityPolicy: &IdentityPolicy{LocalIDType: ikev2.ID_RFC822_ADDR, RequestedIDrType: ikev2.ID_FQDN, Peer: &peer}}
		if err := cfg.ValidateIdentityPolicy(); err != nil {
			t.Fatal(err)
		}
	}
	legacy := &Config{}
	if err := legacy.ValidateIdentityPolicy(); err != nil {
		t.Fatal(err)
	}
	session, _ := identitySession(t)
	session.cfg.APN = "ims"
	payloads, err := session.buildIKEAuthInitPayloads()
	if err != nil || payloads[0].(*ikev2.EncryptedPayloadID).IDType != ikev2.ID_RFC822_ADDR || payloads[1].(*ikev2.EncryptedPayloadID).IDType != ikev2.ID_FQDN {
		t.Fatalf("nil policy changed legacy types: %v", err)
	}
}
