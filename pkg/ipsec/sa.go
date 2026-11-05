package ipsec

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/1239t/swu-go/pkg/crypto"
)

type SecurityAssociation struct {
	SPI           uint32
	RemoteSPI     uint32
	EncryptionAlg crypto.Encrypter
	EncryptionKey []byte
	IntegritySalt []byte // 用于 GCM

	IntegrityAlg  crypto.PRF                // 旧接口 (保留兼容性)
	IntegrityAlg2 crypto.IntegrityAlgorithm // 新接口，用于非 AEAD
	IntegrityKey  []byte

	IsAEAD         bool   // 是否使用 AEAD 加密 (GCM 等)
	SequenceNumber uint64 // Full outbound counter, reserved before encryption.
	ReplayWindow   uint64 // Legacy field retained for API compatibility.
	ESN            bool   // Immutable for this SA; negotiated before first use.

	mu              sync.Mutex
	receiveSequence uint64
	receiveBitmap   uint64
}

func NewSecurityAssociation(spi uint32, enc crypto.Encrypter, encKey []byte, integKey []byte) *SecurityAssociation {
	return &SecurityAssociation{
		SPI:            spi,
		EncryptionAlg:  enc,
		EncryptionKey:  encKey,
		IntegrityKey:   integKey,
		SequenceNumber: 0,
		IsAEAD:         true, // 默认假设 AEAD (GCM)
	}
}

// NewSecurityAssociationCBC 创建使用 CBC + HMAC 的 SA
func NewSecurityAssociationCBC(spi uint32, enc crypto.Encrypter, encKey []byte, integAlg crypto.IntegrityAlgorithm, integKey []byte) *SecurityAssociation {
	return &SecurityAssociation{
		SPI:            spi,
		EncryptionAlg:  enc,
		EncryptionKey:  encKey,
		IntegrityAlg2:  integAlg,
		IntegrityKey:   integKey,
		SequenceNumber: 0,
		IsAEAD:         false,
	}
}

func (sa *SecurityAssociation) NextSequenceNumber() uint32 {
	seq, _ := sa.nextSequenceNumber()
	return uint32(seq)
}

// Reserve before encryption so failures cannot cause sequence or nonce reuse.
// The legacy low-word accessor returns zero on exhaustion without rewinding.
func (sa *SecurityAssociation) nextSequenceNumber() (uint64, error) {
	limit := uint64(math.MaxUint32)
	if sa.ESN {
		limit = math.MaxUint64
	}
	for {
		current := atomic.LoadUint64(&sa.SequenceNumber)
		if current >= limit {
			return 0, errors.New("ESP sequence number exhausted")
		}
		if atomic.CompareAndSwapUint64(&sa.SequenceNumber, current, current+1) {
			return current + 1, nil
		}
	}
}

// RFC 4303 Appendix A, with a 64-packet userspace replay window. The kernel
// replay window remains an independent XFRM setting. The receive mutex covers
// inference, authentication, and commit; failed packets cannot move the window.
func (sa *SecurityAssociation) receiveESN(low uint32) (uint64, error) {
	lastLow, high := uint32(sa.receiveSequence), uint32(sa.receiveSequence>>32)
	if lastLow >= 63 {
		if low < lastLow-63 {
			if high == math.MaxUint32 {
				return 0, errors.New("ESP receive sequence number exhausted")
			}
			high++
		}
	} else if uint64(low) >= (uint64(1)<<32)-(63-uint64(lastLow)) {
		if high == 0 {
			return 0, errors.New("ESP sequence precedes the initial subspace")
		}
		high--
	}
	seq := uint64(high)<<32 | uint64(low)
	if seq == 0 {
		return 0, errors.New("ESP initial sequence number is zero")
	}
	if seq <= sa.receiveSequence {
		distance := sa.receiveSequence - seq
		if distance >= 64 || sa.receiveBitmap&(uint64(1)<<distance) != 0 {
			return 0, errors.New("ESP replayed or stale sequence number")
		}
	}
	return seq, nil
}

func (sa *SecurityAssociation) commitReceiveESN(seq uint64) {
	if seq > sa.receiveSequence {
		distance := seq - sa.receiveSequence
		sa.receiveBitmap = sa.receiveBitmap<<distance | 1
		sa.receiveSequence = seq
	} else {
		sa.receiveBitmap |= uint64(1) << (sa.receiveSequence - seq)
	}
}
