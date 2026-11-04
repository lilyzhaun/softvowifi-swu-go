package swu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"syscall"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

// RFC3526 section 3, independently used by the standard-library peer. No
// production DH constructor or shared-secret function computes the oracle.
const childPFSPrime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

func childPFSPeer(public []byte) (key, shared []byte) {
	p, _ := new(big.Int).SetString(childPFSPrime, 16)
	x := new(big.Int).SetBytes(bytes.Repeat([]byte{0x73}, 32))
	key = new(big.Int).Exp(big.NewInt(2), x, p).FillBytes(make([]byte, 256))
	if public != nil {
		shared = new(big.Int).Exp(new(big.Int).SetBytes(public), x, p).FillBytes(make([]byte, 256))
	}
	return
}

func assertChildPFSKeys(t *testing.T, s *Session, suite peerChildSuite, shared, ni, nr []byte, localInitiator bool) {
	t.Helper()
	e := suite.bits / 8
	if suite.integ == 0 {
		e += 4 // RFC4106: each direction includes its own four-byte salt.
	}
	seed := append(append(append([]byte(nil), shared...), ni...), nr...)
	km := peerChildPRF(s.Keys.SK_d, seed, 2*(e+suite.authBytes))
	ei, ai := km[:e], km[e:e+suite.authBytes]
	er, ar := km[e+suite.authBytes:2*e+suite.authBytes], km[2*e+suite.authBytes:]
	if !localInitiator {
		ei, er, ai, ar = er, ei, ar, ai
	}
	if !bytes.Equal(s.ChildSAOut.EncryptionKey, ei) || !bytes.Equal(s.ChildSAIn.EncryptionKey, er) || !bytes.Equal(s.ChildSAOut.IntegrityKey, ai) || !bytes.Equal(s.ChildSAIn.IntegrityKey, ar) {
		t.Fatal("committed two-way KEYMAT differs from independent new_shared|Ni|Nr PRF+")
	}
	if bytes.Equal(km, peerChildPRF(s.Keys.SK_d, append(bytes.Clone(ni), nr...), len(km))) {
		t.Fatal("fresh DH secret was omitted from KEYMAT")
	}
}

func assertChildPFSFact(t *testing.T, s *Session, group uint16) {
	t.Helper()
	fact := s.Snapshot().Security
	if fact == nil || fact.Child.PFS != group {
		t.Fatalf("actual committed PFS fact missing or differs from %d", group)
	}
}

func TestChildPFSIndependentPRFVectorsAndDirection(t *testing.T) {
	// Synthetic fixed vectors independently precomputed with HMAC-SHA256.
	// Their prefix also anchors the dynamic standard-library oracle used below.
	const vector = "254e47c41da487fa3dc4c509d82e780253d29a494817417b025e9640484f2950119233a901e46f6456c1cc745efc09c808529e39e536d57646cea0f513a928ceb8a5477422775c63991015c3b668df865bcde5b7a4dd3c799ac488e2ae35d2ae"
	const zero = "7676c7ad3107b5b9a5ec63e9747656801948fc75041b99bb4270a59d301920439e6d08df81510a08f7392ce50690b231212f56961425d46373d1b08cdf38890ac68e39a50d51ddf3d2d5a498c6e83703f29e193f6116d472f84882a9a53b6496"
	shared := make([]byte, 256)
	for i := range shared {
		shared[i] = byte(i)
	}
	key, ni, nr := bytes.Clone(shared[:32]), bytes.Clone(shared[32:64]), bytes.Clone(shared[64:96])
	want, _ := hex.DecodeString(vector)
	noPFS, _ := hex.DecodeString(zero)
	if !bytes.Equal(peerChildPRF(key, append(append(bytes.Clone(shared), ni...), nr...), 96), want) || !bytes.Equal(peerChildPRF(key, append(bytes.Clone(ni), nr...), 96), noPFS) {
		t.Fatal("independent HMAC-SHA256 PRF+ disagrees with fixed synthetic vectors")
	}
	for _, suite := range peerChildSuites {
		for _, local := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d_%d_%d_%v", suite.encr, suite.integ, suite.bits, local), func(t *testing.T) {
				s, _, _ := peerChildFixture(t, suite)
				s.Keys.SK_d = key
				next, err := s.deriveChildRekeyWithSecret(suite.encr, suite.integ, suite.bits, ni, nr, 1, 2, local, shared)
				if err != nil {
					t.Fatal(err)
				}
				s.ChildSAIn, s.ChildSAOut = next.in, next.out
				assertChildPFSKeys(t, s, suite, shared, ni, nr, local)
				old, err := s.deriveChildRekey(suite.encr, suite.integ, suite.bits, ni, nr, 1, 2, local)
				if err != nil || bytes.Equal(old.in.EncryptionKey, next.in.EncryptionKey) {
					t.Fatal("zero-PFS derivation changed or equals PFS")
				}
			})
		}
	}
}

func TestChildPFSPolicyCapturesZeroAndExplicitWithNilSuites(t *testing.T) {
	for _, group := range []uint16{0, 14} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d_%v", group, explicit), func(t *testing.T) {
				s := newInitTestSession("")
				s.cfg.ChildPFSGroup = group
				if explicit {
					s.cfg.ESPProposals = []string{"esp-cbc128-sha256-noesn"}
				}
				if _, err := s.buildIKESAInitPacket(); err != nil {
					t.Fatal(err)
				}
				captured := s.proposalPolicy
				s.cfg.ChildPFSGroup = 14 - group
				s.cfg.IKEProposals, s.cfg.ESPProposals = []string{"invalid"}, []string{"invalid"}
				s.childEncrID, s.childIntegID, s.childEncrKeyLenBits = 12, 12, 128
				p, err := s.localChildProposals([]byte{1, 2, 3, 4})
				if err != nil || s.proposalPolicy != captured || captured.childPFS != group {
					t.Fatal("later Config mutation changed the first complete capture")
				}
				for _, proposal := range p {
					count := 0
					for _, tr := range proposal.Transforms {
						if tr.Type == ikev2.TransformTypeDH {
							count++
							if uint16(tr.ID) != group {
								t.Fatal("captured proposal used changed DH")
							}
						}
					}
					if (group == 14 && count != 1) || (group == 0 && count != 0) {
						t.Fatal("captured Child PFS was hot-enabled/disabled")
					}
				}
				for _, initial := range captured.initialChild {
					for _, tr := range initial.Transforms {
						if tr.Type == ikev2.TransformTypeDH {
							t.Fatal("rekey polluted initial IKE_AUTH Child with independent DH")
						}
					}
				}
				fresh := NewSession(s.cfg, zap.NewNop())
				if err := fresh.prepareProposalPolicy(); !errors.Is(err, ErrInvalidProposalPolicy) {
					t.Fatal("fresh owner did not capture its own changed policy")
				}
			})
		}
	}
}

func TestChildPFSInvalidPolicyStopsBeforeSocket(t *testing.T) {
	for _, group := range []uint16{1, 2, 15, 19, 65535} {
		t.Run(fmt.Sprint(group), func(t *testing.T) {
			opened := false
			c := &Config{ChildPFSGroup: group, EpDGAddr: "127.0.0.1", LocalAddr: "127.0.0.1",
				SocketControl: func(string, string, syscall.RawConn) error { opened = true; return errors.New("socket reached") }}
			if err := c.ValidateProposalPolicy(); !errors.Is(err, ErrInvalidProposalPolicy) || c.ChildPFSGroup != group {
				t.Fatal("public validation ignored/changed unsupported PFS")
			}
			s := NewSession(c, zap.NewNop())
			if err := s.Connect(t.Context()); !errors.Is(err, ErrInvalidProposalPolicy) || opened {
				t.Fatal("unsupported Child group reached transport")
			}
			s.Shutdown()
		})
	}
}

// The response is standard-library CBC/HMAC; the request is independently
// opened before selecting one actual offered complete tuple and exact TS.
func exerciseChildPFS(t *testing.T, s *Session, invoke func() error, mutate func([]ikev2.Payload) []ikev2.Payload, onRequest func([]byte)) (shared, ni, nr []byte, err error) {
	t.Helper()
	pipe := s.socket.(*pipeTransport)
	done := make(chan error, 1)
	go func() { done <- invoke() }()
	var raw []byte
	select {
	case raw = <-pipe.sent:
	case <-s.ctx.Done():
		t.Fatal("PFS rekey did not reach actual request")
	}
	opened := peerChildOpen(t, raw, s.Keys.SK_ei, s.Keys.SK_ai)
	ke := opened[byte(ikev2.KE)]
	if len(ke) != 260 || binary.BigEndian.Uint16(ke[:2]) != 14 || bytes.Equal(ke[4:], s.DH.PublicKeyBytes()) {
		t.Fatal("missing/incorrect/freshness-violating local KE")
	}
	key, secret := childPFSPeer(ke[4:])
	shared, ni, nr = secret, bytes.Clone(opened[byte(ikev2.NiNr)]), bytes.Repeat([]byte{0x92}, 32)
	_, request, decodeErr := testPeerReceiver(s).decryptAndParse(raw)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	var selected *ikev2.Proposal
	var selectors []ikev2.Payload
	for _, pl := range request {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			selected = p.Proposals[0]
			selected.SPI = binary.BigEndian.AppendUint32(nil, 0x45454545)
		case *ikev2.EncryptedPayloadTS:
			selectors = append(selectors, p)
		}
	}
	response := append([]ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{selected}}, &ikev2.EncryptedPayloadNonce{NonceData: nr}, &ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: key}}, selectors...)
	if mutate != nil {
		response = mutate(response)
	}
	if onRequest != nil {
		onRequest(raw)
	}
	mid := binary.BigEndian.Uint32(raw[20:24])
	if s.ctx.Err() == nil && !s.taskMgr.HandleResponse(mid, encodePeerPacket(t, s, response, ikev2.CREATE_CHILD_SA, mid, true)) {
		t.Fatal("independent encrypted response did not match actual request")
	}
	select {
	case err = <-done:
	case <-s.ctx.Done():
		select {
		case err = <-done:
		case <-t.Context().Done():
			t.Fatal("PFS cancellation did not return")
		}
	}
	return
}

func TestChildPFSLocalEncryptedRekeySuiteMatrix(t *testing.T) {
	for _, suite := range peerChildSuites {
		t.Run(fmt.Sprintf("%d_%d_%d", suite.encr, suite.integ, suite.bits), func(t *testing.T) {
			s, pipe := childRekeySession(t)
			s.cfg.ChildPFSGroup = 14
			s.PRFAlg, _ = crypto.GetPRF(uint16(ikev2.PRF_HMAC_SHA2_256))
			s.childEncrID, s.childIntegID, s.childEncrKeyLenBits = suite.encr, suite.integ, suite.bits
			s.publishNegotiatedSecurity()
			assertChildPFSFact(t, s, 0)
			oldDH, oldShared := s.DH, bytes.Clone(s.DH.SharedKey)
			kernel := newRekeyKernel()
			shared, ni, nr, err := exerciseChildPFS(t, s, func() error { return s.rekeyChildSA(kernel) }, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertChildPFSKeys(t, s, suite, shared, ni, nr, true)
			assertChildPFSFact(t, s, 14)
			if s.DH != oldDH || !bytes.Equal(s.DH.SharedKey, oldShared) || len(kernel.adds) != 2 {
				t.Fatal("Child DH changed IKE owner or missing two-direction install")
			}
			deleted := peerChildOpen(t, <-pipe.sent, s.Keys.SK_ei, s.Keys.SK_ai)[byte(ikev2.D)]
			if len(deleted) != 8 || binary.BigEndian.Uint32(deleted[4:]) != 102 {
				t.Fatal("PFS local rekey did not delete old inbound SPI")
			}
			s.cancel()
			assertNoNegotiatedSecurity(t, s)
		})
	}
}

func TestChildPFSLocalInvalidResponsesCannotCommitOrDowngrade(t *testing.T) {
	for _, kind := range []string{"missing_ke", "duplicate_ke", "wrong_group", "short_ke", "zero_ke", "one_ke", "prime_ke", "missing_dh", "duplicate_dh", "wrong_dh", "dh_attributes", "notify_group2"} {
		t.Run(kind, func(t *testing.T) {
			s, pipe := childRekeySession(t)
			s.cfg.ChildPFSGroup = 14
			s.publishNegotiatedSecurity()
			snap := snapshotChildRekey(s)
			kernel := newRekeyKernel()
			_, _, _, err := exerciseChildPFS(t, s, func() error { return s.rekeyChildSA(kernel) }, func(p []ikev2.Payload) []ikev2.Payload {
				ke := p[2].(*ikev2.EncryptedPayloadKE)
				proposal := p[0].(*ikev2.EncryptedPayloadSA).Proposals[0]
				mutateChildPFS(kind, ke, proposal)
				switch kind {
				case "missing_ke":
					p = append(p[:2], p[3:]...)
				case "duplicate_ke":
					p = append(p, ke)
				case "notify_group2":
					p = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.INVALID_KE_PAYLOAD, NotifyData: []byte{0, 2}}}
				}
				return p
			}, nil)
			if err == nil || len(kernel.calls) != 0 || len(pipe.sent) != 0 {
				t.Fatal("invalid PFS response committed, retried or reached kernel")
			}
			snap.assertUncommitted(t, s)
			assertChildPFSFact(t, s, 0)
		})
	}
}

func mutateChildPFS(kind string, ke *ikev2.EncryptedPayloadKE, proposal *ikev2.Proposal) {
	switch kind {
	case "wrong_group":
		ke.DHGroup = 2
	case "short_ke":
		ke.KEData = []byte{2}
	case "zero_ke", "one_ke":
		ke.KEData = make([]byte, 256)
		if kind == "one_ke" {
			ke.KEData[255] = 1
		}
	case "prime_ke":
		ke.KEData, _ = hex.DecodeString(childPFSPrime)
	case "missing_dh":
		proposal.Transforms = proposal.Transforms[:len(proposal.Transforms)-1]
	case "duplicate_dh":
		proposal.AddTransform(ikev2.TransformTypeDH, 14, 0)
	case "wrong_dh":
		proposal.Transforms[len(proposal.Transforms)-1].ID = 2
	case "dh_attributes":
		proposal.Transforms[len(proposal.Transforms)-1].Attributes = proposal.Transforms[0].Attributes
	}
}

func peerChildPFSFixture(t *testing.T, suite peerChildSuite) (*Session, *pipeTransport, []ikev2.Payload) {
	t.Helper()
	s, pipe, p := peerChildFixture(t, suite)
	s.cfg.ChildPFSGroup = 14
	// A synthetic authenticated initial pair must include its real current
	// outbound policy, not NewSession's pre-authentication empty slice.
	s.childOutPolicies = []childOutPolicy{{saOut: s.ChildSAOut, tsr: s.tsr}}
	p[1].(*ikev2.EncryptedPayloadSA).Proposals[0].AddTransform(ikev2.TransformTypeDH, 14, 0)
	key, _ := childPFSPeer(nil)
	p = append(p, &ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: key})
	s.publishNegotiatedSecurity()
	return s, pipe, p
}

func TestChildPFSPeerEncryptedRekeySuiteMatrixReplayAndRetirement(t *testing.T) {
	for _, suite := range peerChildSuites {
		t.Run(fmt.Sprintf("%d_%d_%d", suite.encr, suite.integ, suite.bits), func(t *testing.T) {
			s, pipe, p := peerChildPFSFixture(t, suite)
			assertChildPFSFact(t, s, 0)
			in, out, dh := s.ChildSAIn, s.ChildSAOut, s.DH
			kernel := newRekeyKernel()
			kernel.live = map[uint32]bool{in.SPI: true, out.SPI: true}
			raw := encodePeerPacket(t, s, p, ikev2.CREATE_CHILD_SA, 0, false)
			deliverChildPFS(t, s, raw, kernel)
			first := <-pipe.sent
			opened := peerChildOpen(t, first, s.Keys.SK_ei, s.Keys.SK_ai)
			ke := opened[byte(ikev2.KE)]
			if len(ke) != 260 || binary.BigEndian.Uint16(ke[:2]) != 14 || bytes.Equal(ke[4:], dh.PublicKeyBytes()) {
				t.Fatal("peer response omitted/mismatched or reused IKE KE")
			}
			_, shared := childPFSPeer(ke[4:])
			assertChildPFSKeys(t, s, suite, shared, bytes.Repeat([]byte{0xa5}, 32), opened[byte(ikev2.NiNr)], false)
			assertChildPFSFact(t, s, 14)
			if s.DH != dh || len(kernel.adds) != 2 || s.retiredChild == nil {
				t.Fatal("peer PFS violated IKE owner/install/overlap")
			}
			calls := len(kernel.calls)
			deliverChildPFS(t, s, raw, kernel)
			if !bytes.Equal(<-pipe.sent, first) || len(kernel.calls) != calls {
				t.Fatal("replay regenerated KE/response or reinstalled")
			}
			d := &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, out.SPI)}
			if err := s.handleIncomingInformationalParsed(1, []ikev2.Payload{d}); err != nil {
				t.Fatal(err)
			}
			<-pipe.sent
			if !reflect.DeepEqual(kernel.live, map[uint32]bool{s.ChildSAIn.SPI: true, s.ChildSAOut.SPI: true}) || s.ChildSAsIn[in.SPI] != nil {
				t.Fatal("PFS predecessor Delete did not clean only the old pair")
			}
			assertChildPFSFact(t, s, 14)
			s.cancel()
			assertNoNegotiatedSecurity(t, s)
		})
	}
}

func TestChildPFSPeerInvalidRequestsCannotInstallOrDowngrade(t *testing.T) {
	for _, kind := range []string{"missing_ke", "duplicate_ke", "wrong_group", "short_ke", "zero_ke", "one_ke", "prime_ke", "missing_dh", "duplicate_dh", "wrong_dh", "dh_attributes", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			s, pipe, p := peerChildPFSFixture(t, peerChildSuites[2])
			ke := p[5].(*ikev2.EncryptedPayloadKE)
			mutateChildPFS(kind, ke, p[1].(*ikev2.EncryptedPayloadSA).Proposals[0])
			switch kind {
			case "missing_ke":
				p = p[:5]
			case "duplicate_ke":
				p = append(p, ke)
			case "disabled":
				s.cfg.ChildPFSGroup = 0
			}
			snap := snapshotChildRekey(s)
			kernel := newRekeyKernel()
			deliverChildPFS(t, s, encodePeerPacket(t, s, p, ikev2.CREATE_CHILD_SA, 0, false), kernel)
			reply := peerChildOpen(t, <-pipe.sent, s.Keys.SK_ei, s.Keys.SK_ai)
			if len(reply[byte(ikev2.SA)]) != 0 || len(reply[byte(ikev2.N)]) < 4 || len(kernel.calls) != 0 {
				t.Fatal("invalid PFS request installed or was accepted")
			}
			if kind == "wrong_group" && !bytes.Equal(reply[byte(ikev2.N)], []byte{0, 0, 0, 17, 0, 14}) {
				t.Fatal("INVALID_KE did not advertise only configured group14")
			}
			snap.assertUncommitted(t, s)
			assertChildPFSFact(t, s, 0)
		})
	}
}

func TestChildPFSPeerFailureAndCancellationKeepOldSnapshot(t *testing.T) {
	for _, failure := range []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4", "send", "cancel", "cancel_during_send"} {
		t.Run(failure, func(t *testing.T) {
			s, pipe, p := peerChildPFSFixture(t, peerChildSuites[2])
			snap := snapshotChildRekey(s)
			kernel := newRekeyKernel()
			kernel.live = map[uint32]bool{snap.in.SPI: true, snap.out.SPI: true}
			kernel.fail = failure
			if failure == "send" {
				pipe.sendErr = errSendIKE
			}
			if failure == "cancel_during_send" {
				pipe.beforeSend = s.cancel
			}
			kernel.before = func() {
				snap.assertUncommitted(t, s)
				if s.ctx.Err() == nil {
					assertChildPFSFact(t, s, 0)
				}
				if failure == "cancel" && len(kernel.adds) == 2 {
					s.cancel()
				}
			}
			if err := s.handlePeerChildRekey(0, p, kernel); err == nil || s.retiredChild != nil || !reflect.DeepEqual(kernel.live, map[uint32]bool{snap.in.SPI: true, snap.out.SPI: true}) {
				t.Fatal("PFS failed transaction published or leaked new kernel pair")
			}
			snap.assertUncommitted(t, s)
			if failure == "cancel" || failure == "cancel_during_send" {
				assertNoNegotiatedSecurity(t, s)
			} else {
				assertChildPFSFact(t, s, 0)
			}
		})
	}
}

func TestChildPFSLocalFailureAndCancellationKeepOldSnapshot(t *testing.T) {
	for _, failure := range []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4", "del101", "del102", "cancel", "cancel_during_install"} {
		t.Run(failure, func(t *testing.T) {
			s, pipe := childRekeySession(t)
			s.cfg.ChildPFSGroup = 14
			s.publishNegotiatedSecurity()
			snap := snapshotChildRekey(s)
			kernel := newRekeyKernel()
			kernel.fail = failure
			kernel.before = func() {
				snap.assertUncommitted(t, s)
				if failure == "cancel_during_install" && len(kernel.adds) == 2 {
					s.cancel()
				}
			}
			_, _, _, err := exerciseChildPFS(t, s, func() error { return s.rekeyChildSA(kernel) }, nil, func([]byte) {
				if failure == "cancel" {
					s.cancel()
				}
			})
			if err == nil || len(pipe.sent) != 0 {
				t.Fatal("failed/canceled PFS local rekey committed or sent Delete")
			}
			snap.assertUncommitted(t, s)
			if failure == "cancel" || failure == "cancel_during_install" {
				assertNoNegotiatedSecurity(t, s)
			} else {
				assertChildPFSFact(t, s, 0)
			}
		})
	}
}

func TestChildPFSZeroPolicyIsNotHotEnabledAtActualRekey(t *testing.T) {
	s, _ := childRekeySession(t)
	if err := s.prepareProposalPolicy(); err != nil {
		t.Fatal(err)
	}
	s.cfg.ChildPFSGroup = 14
	s.publishNegotiatedSecurity()
	if err := exerciseChildRekey(t, s, s.RekeyChildSA); err != nil {
		t.Fatal(err)
	}
	assertChildPFSFact(t, s, 0)
}

func deliverChildPFS(t *testing.T, s *Session, raw []byte, ops childRekeyXFRMOps) {
	t.Helper()
	mid, payloads, err := s.decryptAndParse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.handleIncomingCreateChildSAParsed(mid, payloads, ops); err != nil {
		t.Fatal(err)
	}
}
