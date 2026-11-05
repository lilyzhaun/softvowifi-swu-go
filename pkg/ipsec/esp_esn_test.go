package ipsec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sync"
	"testing"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
)

var esnTestPlain = []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1}
var esnTestKey = []byte("1234567890123456salt")
var esnTestIntegrityKey = bytes.Repeat([]byte{0x5a}, 32)

func esnTestSA(t *testing.T, aead, esn bool) *SecurityAssociation {
	t.Helper()
	id := uint16(12)
	if aead {
		id = 20
	}
	enc, err := swucrypto.GetEncrypter(id)
	if err != nil {
		t.Fatal(err)
	}
	var sa *SecurityAssociation
	if aead {
		sa = NewSecurityAssociation(0x10203040, enc, bytes.Clone(esnTestKey), nil)
	} else {
		integ, err := swucrypto.GetIntegrityAlgorithm(12)
		if err != nil {
			t.Fatal(err)
		}
		sa = NewSecurityAssociationCBC(0x10203040, enc, bytes.Clone(esnTestKey[:16]), integ, bytes.Clone(esnTestIntegrityKey))
	}
	// Reach the existing real consumer on the old implementation. A missing
	// future ESN input must produce a wire-level RED, not a compilation error.
	if esn {
		field := reflect.ValueOf(sa).Elem().FieldByName("ESN")
		if field.IsValid() && field.CanSet() && field.Kind() == reflect.Bool {
			field.SetBool(true)
		}
	}
	return sa
}

func esnTestAAD(spi uint32, seq uint64, esn bool) []byte {
	size := 8
	if esn {
		size = 12
	}
	aad := make([]byte, size)
	binary.BigEndian.PutUint32(aad, spi)
	if esn {
		binary.BigEndian.PutUint64(aad[4:], seq)
	} else {
		binary.BigEndian.PutUint32(aad[4:], uint32(seq))
	}
	return aad
}

// Build a peer packet without calling production crypto, ESP, padding, or
// sequence helpers. High words authenticate but are not appended to the wire.
func esnPeerPacket(t *testing.T, seq uint64, aead, esn bool) []byte {
	t.Helper()
	block, err := aes.NewCipher(esnTestKey[:16])
	if err != nil {
		t.Fatal(err)
	}
	align := 16
	if aead {
		align = 4
	}
	pad := (align - (len(esnTestPlain)+2)%align) % align
	plain := bytes.Clone(esnTestPlain)
	for n := 1; n <= pad; n++ {
		plain = append(plain, byte(n))
	}
	plain = append(plain, byte(pad), 4)
	packet := make([]byte, 8)
	binary.BigEndian.PutUint32(packet, 0x10203040)
	binary.BigEndian.PutUint32(packet[4:], uint32(seq))
	iv := make([]byte, 8)
	binary.BigEndian.PutUint64(iv, seq)
	if aead {
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		nonce := append(bytes.Clone(esnTestKey[16:]), iv...)
		packet = append(packet, iv...)
		return append(packet, gcm.Seal(nil, nonce, plain, esnTestAAD(0x10203040, seq, esn))...)
	}
	iv = append(iv, bytes.Repeat([]byte{0x36}, 8)...)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, plain)
	packet = append(packet, iv...)
	packet = append(packet, enc...)
	mac := hmac.New(sha256.New, esnTestIntegrityKey)
	mac.Write(packet)
	if esn {
		high := make([]byte, 4)
		binary.BigEndian.PutUint32(high, uint32(seq>>32))
		mac.Write(high)
	}
	return append(packet, mac.Sum(nil)[:16]...)
}

func TestESPESNOutboundIndependentAuthentication(t *testing.T) {
	for _, aead := range []bool{true, false} {
		for _, seq := range []uint64{1, 0xffffffff, 0x100000000, 0x100000001} {
			t.Run(fmt.Sprintf("aead=%t/seq=%x", aead, seq), func(t *testing.T) {
				sa := esnTestSA(t, aead, true)
				sa.SequenceNumber = seq - 1
				packet, err := Encapsulate(esnTestPlain, sa)
				if err != nil || len(packet) < 32 || binary.BigEndian.Uint32(packet[4:8]) != uint32(seq) {
					t.Fatal("real ESP did not produce the expected low sequence")
				}
				if aead {
					if binary.BigEndian.Uint64(packet[8:16]) != seq {
						t.Fatal("ESN explicit IV is not the unique full sequence")
					}
					block, _ := aes.NewCipher(esnTestKey[:16])
					gcm, _ := cipher.NewGCM(block)
					nonce := append(bytes.Clone(esnTestKey[16:]), packet[8:16]...)
					plain, err := gcm.Open(nil, nonce, packet[16:], esnTestAAD(0x10203040, seq, true))
					if err != nil || len(plain) < 2+len(esnTestPlain) || !bytes.Equal(plain[:len(esnTestPlain)], esnTestPlain) {
						t.Fatal("real GCM ESP does not authenticate SPI and the full sequence")
					}
				} else {
					mac := hmac.New(sha256.New, esnTestIntegrityKey)
					mac.Write(packet[:len(packet)-16])
					high := make([]byte, 4)
					binary.BigEndian.PutUint32(high, uint32(seq>>32))
					mac.Write(high)
					if !hmac.Equal(packet[len(packet)-16:], mac.Sum(nil)[:16]) {
						t.Fatal("real CBC ESP does not authenticate the appended high sequence word")
					}
				}
			})
		}
	}
}

func TestESPESNInboundWrapAndAuthenticatedReplayWindow(t *testing.T) {
	for _, aead := range []bool{true, false} {
		t.Run(fmt.Sprintf("aead=%t", aead), func(t *testing.T) {
			sa := esnTestSA(t, aead, true)
			for _, seq := range []uint64{1, 0xffffff00, 0xfffffffe, 0x100000000, 0xffffffff, 0x100000001} {
				packet := esnPeerPacket(t, seq, aead, true)
				plain, err := Decapsulate(packet, sa)
				if err != nil || !bytes.Equal(plain, esnTestPlain) {
					t.Fatalf("real inbound ESP failed authenticated sequence %x", seq)
				}
				if _, err := Decapsulate(packet, sa); err == nil {
					t.Fatal("authenticated duplicate was accepted twice")
				}
			}
			if _, err := Decapsulate(esnPeerPacket(t, 1, aead, true), sa); err == nil {
				t.Fatal("packet older than the replay window was accepted")
			}
			forged := esnPeerPacket(t, 0x100001000, aead, true)
			forged[len(forged)-1] ^= 1
			if _, err := Decapsulate(forged, sa); err == nil {
				t.Fatal("unauthenticated future sequence was accepted")
			}
			if _, err := Decapsulate(esnPeerPacket(t, 0x100000002, aead, true), sa); err != nil {
				t.Fatal("failed authentication advanced the replay window")
			}
		})
	}
}

func TestESPSequenceExhaustionNeverWrapsToZero(t *testing.T) {
	for _, esn := range []bool{false, true} {
		t.Run(fmt.Sprintf("esn=%t", esn), func(t *testing.T) {
			sa := esnTestSA(t, true, esn)
			sa.SequenceNumber = math.MaxUint32
			if esn {
				sa.SequenceNumber = math.MaxUint64
			}
			before := sa.SequenceNumber
			for n := 0; n < 2; n++ {
				if packet, err := Encapsulate(esnTestPlain, sa); err == nil || len(packet) != 0 || sa.SequenceNumber != before {
					t.Fatal("exhausted sequence produced a packet or rewound the counter")
				}
			}
		})
	}
}

func TestESPNoESNIndependentPeerCompatibility(t *testing.T) {
	for _, aead := range []bool{true, false} {
		t.Run(fmt.Sprintf("aead=%t", aead), func(t *testing.T) {
			plain, err := Decapsulate(esnPeerPacket(t, 1, aead, false), esnTestSA(t, aead, false))
			if err != nil || !bytes.Equal(plain, esnTestPlain) {
				t.Fatal("original non-ESN peer compatibility changed")
			}
		})
	}
}

func TestESPESNConcurrentSequenceAndDuplicateReceive(t *testing.T) {
	for _, aead := range []bool{true, false} {
		t.Run(fmt.Sprintf("aead=%t", aead), func(t *testing.T) {
			out := esnTestSA(t, aead, true)
			out.SequenceNumber = 0xfffffff0
			type result struct {
				packet []byte
				err    error
			}
			results := make(chan result, 32)
			var workers sync.WaitGroup
			for n := 0; n < 32; n++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					packet, err := Encapsulate(esnTestPlain, out)
					results <- result{packet, err}
				}()
			}
			workers.Wait()
			seen := map[uint32]bool{}
			for n := 0; n < 32; n++ {
				r := <-results
				if r.err != nil || len(r.packet) < 16 {
					t.Fatal("concurrent sequence allocation failed")
				}
				seq := binary.BigEndian.Uint32(r.packet[4:8])
				if seen[seq] {
					t.Fatal("concurrent ESP reused a sequence")
				}
				seen[seq] = true
			}
			if out.SequenceNumber != 0x100000010 {
				t.Fatal("concurrent allocation did not retain the full counter")
			}
			in := esnTestSA(t, aead, true)
			packet := esnPeerPacket(t, 1, aead, true)
			for n := 0; n < 32; n++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					plain, err := Decapsulate(packet, in)
					results <- result{plain, err}
				}()
			}
			workers.Wait()
			accepted := 0
			for n := 0; n < 32; n++ {
				if r := <-results; r.err == nil && bytes.Equal(r.packet, esnTestPlain) {
					accepted++
				}
			}
			if accepted != 1 {
				t.Fatal("concurrent duplicate must commit exactly once")
			}
		})
	}
}

func TestESPESNZeroAndOldPacketsNeverAdvanceWindow(t *testing.T) {
	for _, aead := range []bool{true, false} {
		sa := esnTestSA(t, aead, true)
		if _, err := Decapsulate(esnPeerPacket(t, 0, aead, true), sa); err == nil {
			t.Fatal("sequence zero was accepted")
		}
		for _, seq := range []uint64{1, 1000, 937} {
			if _, err := Decapsulate(esnPeerPacket(t, seq, aead, true), sa); err != nil {
				t.Fatal("valid in-window packet was rejected")
			}
		}
		top, bitmap := sa.receiveSequence, sa.receiveBitmap
		for _, seq := range []uint64{936, 1, 937} {
			if _, err := Decapsulate(esnPeerPacket(t, seq, aead, true), sa); err == nil {
				t.Fatal("old or duplicate packet was accepted")
			}
			if sa.receiveSequence != top || sa.receiveBitmap != bitmap {
				t.Fatal("rejected packet changed authenticated replay state")
			}
		}
	}
}

func TestESPESNWithoutAuthenticationCannotSendOrAdvanceReplay(t *testing.T) {
	t.Run("outbound", func(t *testing.T) {
		sa := esnTestSA(t, false, true)
		sa.IntegrityAlg2 = nil
		if packet, err := Encapsulate(esnTestPlain, sa); err == nil || len(packet) != 0 {
			t.Fatal("unauthenticated ESN CBC configuration produced an ESP packet")
		}
	})
	t.Run("inbound", func(t *testing.T) {
		sa := esnTestSA(t, false, true)
		sa.IntegrityAlg2 = nil
		packet := esnPeerPacket(t, 1, false, true)
		if _, err := Decapsulate(packet[:len(packet)-16], sa); err == nil {
			t.Fatal("ESN CBC without an integrity algorithm accepted unauthenticated payload")
		}
		if sa.receiveSequence != 0 || sa.receiveBitmap != 0 {
			t.Fatal("unauthenticated payload advanced the replay window")
		}
	})
}
