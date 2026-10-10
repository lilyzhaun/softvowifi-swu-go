package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// Independent RFC7383 peer. Neither the outgoing SKF builder nor the receive
// decoder is used to construct the authenticated test datagrams.
func independentSKF(t *testing.T, s *Session, inner []byte, first ikev2.PayloadType, number, total uint16, exchange ikev2.ExchangeType, mid uint32, response bool) []byte {
	t.Helper()
	key, macKey := s.Keys.SK_er, s.Keys.SK_ar
	flags := byte(0)
	if s.localResponder {
		key, macKey, flags = s.Keys.SK_ei, s.Keys.SK_ai, ikev2.FlagInitiator
	}
	if response {
		flags |= ikev2.FlagResponse
	}
	pad, ivSize, tag := 0, 16, 16
	if s.ikeIsAEAD {
		ivSize = 8
	} else {
		pad = (16 - (len(inner)+1)%16) % 16
	}
	plain := append(bytes.Clone(inner), make([]byte, pad)...)
	plain = append(plain, byte(pad))
	raw := binary.BigEndian.AppendUint64(nil, s.SPIi)
	raw = binary.BigEndian.AppendUint64(raw, s.SPIr)
	raw = append(raw, 53, 0x20, byte(exchange), flags)
	raw = binary.BigEndian.AppendUint32(raw, mid)
	raw = binary.BigEndian.AppendUint32(raw, uint32(36+ivSize+len(plain)+tag))
	raw = append(raw, byte(first), 0)
	raw = binary.BigEndian.AppendUint16(raw, uint16(8+ivSize+len(plain)+tag))
	raw = binary.BigEndian.AppendUint16(raw, number)
	raw = binary.BigEndian.AppendUint16(raw, total)
	iv := bytes.Repeat([]byte{byte(number + 3)}, ivSize)
	if s.ikeIsAEAD {
		block, err := aes.NewCipher(key[:len(key)-4])
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		sealed := gcm.Seal(nil, append(bytes.Clone(key[len(key)-4:]), iv...), plain, raw)
		return append(append(raw, iv...), sealed...)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	raw = append(append(raw, iv...), plain...)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(raw)
	return append(raw, mac.Sum(nil)[:16]...)
}

func fragmentFixture(t *testing.T, aead, role bool) *Session {
	t.Helper()
	if aead {
		return receiveGCMFixture(t, role)
	}
	s, _ := newPostEAPSession(t)
	s.localResponder = role
	return s
}

func TestFragmentCompleteRetainsFirstType(t *testing.T) {
	inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
	for _, aead := range []bool{false, true} {
		for _, role := range []bool{false, true} {
			for _, order := range [][]int{{1, 2, 3}, {2, 3, 1}, {2, 1, 3}, {1, 1, 3, 2}} {
				t.Run(fmt.Sprintf("AEAD=%v/%s/%v", aead, fmtRole(role), order), func(t *testing.T) {
					s := fragmentFixture(t, aead, role)
					chunks := [][]byte{inner[:2], inner[2:5], inner[5:]}
					for index, number := range order {
						first := ikev2.NoNextPayload
						if number == 1 {
							first = ikev2.N
						}
						mid, pls, err := s.decryptAndParse(independentSKF(t, s, chunks[number-1], first, uint16(number), 3, ikev2.IKE_AUTH, 9, true))
						if err != nil || mid != 9 {
							t.Fatalf("legitimate fragment rejected: %v", err)
						}
						if index+1 < len(order) {
							if len(pls) != 0 {
								t.Fatal("partial message dispatched")
							}
							continue
						}
						if len(pls) != 1 || pls[0].Type() != ikev2.N {
							t.Fatal("complete message lost the first fragment payload type")
						}
					}
				})
			}
		}
	}
}

func TestFragmentWindowWaitsForAuthenticatedWholeMessage(t *testing.T) {
	for _, variant := range []string{"ordered", "reordered", "bad ICV", "bad full chain"} {
		t.Run(variant, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			manager, sends := newIdleWindow(t, 1)
			s.taskMgr = manager
			manager.responseValidator = s.validateWindowResponse
			completion := manager.EnqueueRequest(9, ikev2.IKE_AUTH, nil, nil)
			manager.EnqueueRequest(10, ikev2.INFORMATIONAL, nil, nil)
			past := time.Unix(1, 0)
			s.initializeInboundActivity(past)
			inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
			if variant == "bad full chain" {
				inner[3] = 7
			}
			one := independentSKF(t, s, inner[:4], ikev2.N, 1, 2, ikev2.IKE_AUTH, 9, true)
			two := independentSKF(t, s, inner[4:], 0, 2, 2, ikev2.IKE_AUTH, 9, true)
			if variant == "reordered" {
				one, two = two, one
			}
			commits := 0
			s.dispatchReceivedIKE(one, func() error { commits++; return nil })
			select {
			case <-completion:
				t.Fatal("first fragment consumed pending")
			default:
			}
			manager.mu.Lock()
			pending, queued := len(manager.pending), len(manager.queue)
			manager.mu.Unlock()
			if commits != 0 || !s.lastInboundTime.Equal(past) || pending != 1 || queued != 1 || len(sends) != 1 {
				t.Fatal("partial message committed endpoint/activity or released FIFO")
			}
			if variant == "bad ICV" {
				before := reflect.ValueOf(s.fragmentBuf.frags).Len()
				bad := bytes.Clone(two)
				bad[len(bad)-1] ^= 1
				s.dispatchReceivedIKE(bad, func() error { commits++; return nil })
				if reflect.ValueOf(s.fragmentBuf.frags).Len() != before || commits != 0 {
					t.Fatal("invalid ICV modified authenticated cache")
				}
			}
			s.dispatchReceivedIKE(two, func() error { commits++; return nil })
			if variant == "bad full chain" {
				select {
				case <-completion:
					t.Fatal("malformed whole chain consumed pending")
				default:
				}
				if commits != 0 || !s.lastInboundTime.Equal(past) {
					t.Fatal("bad full chain committed state")
				}
				return
			}
			select {
			case <-completion:
			default:
				t.Fatal("authenticated complete response did not complete original request")
			}
			if commits != 1 || !s.lastInboundTime.After(past) || len(sends) != 2 {
				t.Fatal("complete response was not committed exactly once")
			}
			s.dispatchReceivedIKE(two, func() error { commits++; return nil })
			if commits != 1 {
				t.Fatal("late fragment revived completed request")
			}
		})
	}
}

func TestFragmentMetadataAndIsolation(t *testing.T) {
	for _, variant := range []string{"later type", "first absent type", "foreign exchange", "opposite direction", "new SA keys", "conflicting duplicate"} {
		t.Run(variant, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
			first := ikev2.N
			if variant == "first absent type" {
				first = 0
			}
			_, _, err := s.decryptAndParse(independentSKF(t, s, inner[:4], first, 1, 2, ikev2.IKE_AUTH, 9, true))
			if variant == "first absent type" {
				if err == nil {
					t.Fatal("first fragment omitted next payload")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			secondType := ikev2.NoNextPayload
			exchange := ikev2.IKE_AUTH
			response := true
			if variant == "later type" {
				secondType = ikev2.N
			}
			if variant == "foreign exchange" {
				exchange = ikev2.INFORMATIONAL
			}
			if variant == "opposite direction" {
				response = false
			}
			if variant == "new SA keys" {
				copyKeys := *s.Keys
				s.Keys = &copyKeys
			}
			if variant == "conflicting duplicate" {
				_, _, err = s.decryptAndParse(independentSKF(t, s, []byte{0, 0, 0, 7}, ikev2.N, 1, 2, exchange, 9, true))
				if err == nil {
					t.Fatal("conflicting duplicate silently ignored")
				}
				return
			}
			_, payloads, err := s.decryptAndParse(independentSKF(t, s, inner[4:], secondType, 2, 2, exchange, 9, response))
			if variant == "later type" {
				if err == nil {
					t.Fatal("non-first fragment has a payload type")
				}
				return
			}
			if err != nil || len(payloads) != 0 {
				t.Fatalf("foreign transaction was merged: %v", err)
			}
			if len(s.fragmentBuf.frags) != 2 {
				t.Fatal("SA generation/direction/exchange did not isolate equal MIDs")
			}
		})
	}
}

func TestFragmentInflightSetsBounded(t *testing.T) {
	s, _ := newPostEAPSession(t)
	for mid := uint32(1); mid <= 17; mid++ {
		_, _, err := s.decryptAndParse(independentSKF(t, s, []byte{0}, ikev2.N, 1, 2, ikev2.INFORMATIONAL, mid, false))
		if mid <= 16 && err != nil {
			t.Fatal(err)
		}
		if mid == 17 && err == nil {
			t.Fatal("unbounded authenticated fragment queues")
		}
	}
	if len(s.fragmentBuf.frags) != 16 {
		t.Fatal("fragment queue cap not enforced")
	}
}

func (peer *akaWirePeer) sendFragmented(t *testing.T, payloads []akaWirePayload, reorder bool) {
	t.Helper()
	var inner []byte
	for index, pl := range payloads {
		next := byte(0)
		if index+1 < len(payloads) {
			next = payloads[index+1].kind
		}
		inner = append(inner, next, 0)
		inner = binary.BigEndian.AppendUint16(inner, uint16(4+len(pl.body)))
		inner = append(inner, pl.body...)
	}
	peer.header.MessageID++
	s := &Session{SPIi: peer.header.SPIi, SPIr: peer.header.SPIr, Keys: &ikev2.IKESAKeys{SK_er: peer.keys[128:160], SK_ar: peer.keys[64:96]}}
	total := (len(inner) + 159) / 160
	packets := make([][]byte, total)
	for index := range packets {
		end := min(len(inner), (index+1)*160)
		first := ikev2.NoNextPayload
		if index == 0 {
			first = ikev2.PayloadType(payloads[0].kind)
		}
		packets[index] = independentSKF(t, s, inner[index*160:end], first, uint16(index+1), uint16(total), ikev2.IKE_AUTH, peer.header.MessageID, true)
	}
	if reorder {
		for index := len(packets) - 1; index >= 0; index-- {
			peer.send(t, packets[index])
		}
		return
	}
	for _, raw := range packets {
		peer.send(t, raw)
	}
}
