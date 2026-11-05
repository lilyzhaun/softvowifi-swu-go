package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func assertESNPairTraffic(t *testing.T, s *Session) {
	t.Helper()
	if !s.childESN || s.ChildSAOut == nil || s.ChildSAIn == nil || !s.ChildSAOut.ESN || !s.ChildSAIn.ESN {
		t.Fatal("authenticated ESN did not reach both actual ESP consumers")
	}
	plain := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1}
	for _, inbound := range []bool{false, true} {
		actual := s.ChildSAOut
		if inbound {
			actual = s.ChildSAIn
		}
		var peer *ipsec.SecurityAssociation
		if actual.IsAEAD {
			peer = ipsec.NewSecurityAssociation(actual.SPI, actual.EncryptionAlg, bytes.Clone(actual.EncryptionKey), nil)
		} else {
			peer = ipsec.NewSecurityAssociationCBC(actual.SPI, actual.EncryptionAlg, bytes.Clone(actual.EncryptionKey), actual.IntegrityAlg2, bytes.Clone(actual.IntegrityKey))
		}
		peer.ESN = true // Peer expectation; the actual local flag was asserted above.
		sender, receiver := actual, peer
		if inbound {
			sender, receiver = peer, actual
		}
		for _, seq := range []uint64{1, 0xffffff00, 0xffffffff, 0x100000000, 0x100000001} {
			atomic.StoreUint64(&sender.SequenceNumber, seq-1)
			packet, err := ipsec.Encapsulate(plain, sender)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := ipsec.Decapsulate(packet, receiver)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("actual authenticated/rekeyed SA lost cross-word ESP interoperability")
			}
			if _, err := ipsec.Decapsulate(packet, receiver); err == nil {
				t.Fatal("actual authenticated/rekeyed receiver accepted a duplicate")
			}
		}
	}
}

func TestESNFullConnectIndependentAKAAndESP(t *testing.T) {
	testAKAIdentityAUTH(t, "unfragmented", true)
}

func assertESNCompleteOfferBytes(t *testing.T, body []byte) {
	t.Helper()
	proposals := 0
	for offset := 0; offset < len(body); {
		if len(body)-offset < 12 {
			t.Fatal("short ESP proposal in actual protected AUTH")
		}
		length := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		if length < 12 || offset+length > len(body) || body[offset+5] != 3 || body[offset+6] != 4 {
			t.Fatal("invalid actual complete ESP proposal")
		}
		count := 0
		for cursor := offset + 12; cursor < offset+length; {
			if offset+length-cursor < 8 {
				t.Fatal("short transform in actual ESP offer")
			}
			n := int(binary.BigEndian.Uint16(body[cursor+2 : cursor+4]))
			if n < 8 || cursor+n > offset+length {
				t.Fatal("invalid actual transform length")
			}
			if body[cursor+4] == 5 {
				count++
				if n != 8 || binary.BigEndian.Uint16(body[cursor+6:cursor+8]) != 1 {
					t.Fatal("actual UDP AUTH offer did not authenticate an explicit ESN choice")
				}
			}
			cursor += n
		}
		if count != 1 {
			t.Fatal("actual complete ESP proposal omitted mandatory ESN")
		}
		proposals++
		offset += length
	}
	if proposals != 6 {
		t.Fatal("ESN opt-in changed the original complete proposal count")
	}
}

func TestESNAuthenticatedLocalAndPeerRekeyPreserveESPMode(t *testing.T) {
	for _, suite := range []uint8{2, 4} {
		for _, peerInitiated := range []bool{false, true} {
			t.Run(strconv.Itoa(int(suite))+"/peer="+strconv.FormatBool(peerInitiated), func(t *testing.T) {
				s, _ := newPostEAPSession(t, func(c *Config) { c.EnableESN = true })
				payloads := childTransactionPayloads(t, s)
				payloads[3] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{esnSelectedProposal(suite, 1)}}
				if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
					t.Fatal(err)
				}
				assertESNPairTraffic(t, s)
				pipe := &pipeTransport{sent: make(chan []byte, 8)}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				s.ctx, s.cancel, s.socket, s.ikeControlAlive = ctx, cancel, pipe, true
				t.Cleanup(cancel)
				s.taskMgr = NewTaskManager(ctx, nil, 1, func(packets [][]byte) error {
					for _, packet := range packets {
						if err := pipe.SendIKE(packet); err != nil {
							return err
						}
					}
					return nil
				})
				t.Cleanup(s.taskMgr.Stop)
				s.rekeyResetCh, s.childRekeyResetCh = make(chan struct{}, 1), make(chan struct{}, 1)
				s.SequenceNumber.Store(4) // Continue after the authenticated response MID 3.
				old := s.ChildSAIn
				if peerInitiated {
					selected := esnSelectedProposal(suite, 1)
					selected.ProposalNum, selected.SPI = 1, binary.BigEndian.AppendUint32(nil, 0x33333333)
					request := []ikev2.Payload{
						&ikev2.EncryptedPayloadNotify{ProtocolID: ikev2.ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, s.ChildSAOut.SPI), NotifyType: ikev2.REKEY_SA},
						&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{selected}},
						&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0xa5}, 32)},
						&ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsr},
						&ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: s.tsi},
					}
					s.dispatchReceivedIKE(encodePeerPacket(t, s, request, ikev2.CREATE_CHILD_SA, 0, false), nil)
					select {
					case raw := <-pipe.sent:
						response := peerChildOpen(t, raw, s.Keys.SK_ei, s.Keys.SK_ai)
						if len(response[byte(ikev2.SA)]) == 0 {
							t.Fatal("production peer dispatcher did not accept the ESN rekey")
						}
					case <-ctx.Done():
						t.Fatal("production peer dispatcher did not reply")
					}
				} else if err := exerciseChildRekey(t, s, s.RekeyChildSA); err != nil {
					t.Fatal(err)
				}
				if s.ChildSAIn == old {
					t.Fatal("real authenticated rekey did not publish a new SA pair")
				}
				assertESNPairTraffic(t, s)
			})
		}
	}
}
