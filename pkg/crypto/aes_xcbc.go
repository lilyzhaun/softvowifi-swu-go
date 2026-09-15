package crypto

import (
	"crypto/aes"
	"fmt"
)

type aes128XCBCPRF struct{}

func (p *aes128XCBCPRF) Compute(key, data []byte) ([]byte, error) {
	normalizedKey, err := normalizeAES128XCBCKey(key)
	if err != nil {
		return nil, fmt.Errorf("normalize AES-XCBC PRF key: %w", err)
	}

	mac, err := computeAESXCBCMAC(normalizedKey, data)
	if err != nil {
		return nil, fmt.Errorf("compute AES-XCBC PRF: %w", err)
	}
	return mac[:], nil
}

func (p *aes128XCBCPRF) KeyLen() int {
	return aes.BlockSize
}

func (p *aes128XCBCPRF) FixedKeySize() bool {
	return true
}

func normalizeAES128XCBCKey(key []byte) ([aes.BlockSize]byte, error) {
	var normalized [aes.BlockSize]byte
	if len(key) <= aes.BlockSize {
		copy(normalized[:], key)
		return normalized, nil
	}

	mac, err := computeAESXCBCMAC(normalized, key)
	if err != nil {
		return normalized, fmt.Errorf("shorten AES-XCBC PRF key: %w", err)
	}
	return mac, nil
}

func computeAESXCBCMAC(key [aes.BlockSize]byte, message []byte) ([aes.BlockSize]byte, error) {
	var zero [aes.BlockSize]byte
	rootCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return zero, fmt.Errorf("initialize AES-XCBC root cipher: %w", err)
	}

	var constant1, constant2, constant3 [aes.BlockSize]byte
	for i := range constant1 {
		constant1[i] = 0x01
		constant2[i] = 0x02
		constant3[i] = 0x03
	}

	var key1, key2, key3 [aes.BlockSize]byte
	rootCipher.Encrypt(key1[:], constant1[:])
	rootCipher.Encrypt(key2[:], constant2[:])
	rootCipher.Encrypt(key3[:], constant3[:])

	workingCipher, err := aes.NewCipher(key1[:])
	if err != nil {
		return zero, fmt.Errorf("initialize AES-XCBC working cipher: %w", err)
	}

	completeFinalBlock := len(message) > 0 && len(message)%aes.BlockSize == 0
	prefixBlocks := len(message) / aes.BlockSize
	if completeFinalBlock {
		prefixBlocks--
	}

	var chainingValue, block [aes.BlockSize]byte
	for blockIndex := 0; blockIndex < prefixBlocks; blockIndex++ {
		start := blockIndex * aes.BlockSize
		for i := range block {
			block[i] = message[start+i] ^ chainingValue[i]
		}
		workingCipher.Encrypt(chainingValue[:], block[:])
	}

	block = [aes.BlockSize]byte{}
	finalStart := prefixBlocks * aes.BlockSize
	copy(block[:], message[finalStart:])
	finalKey := key3
	if completeFinalBlock {
		finalKey = key2
	} else {
		block[len(message)-finalStart] = 0x80
	}
	for i := range block {
		block[i] ^= chainingValue[i] ^ finalKey[i]
	}

	var mac [aes.BlockSize]byte
	workingCipher.Encrypt(mac[:], block[:])
	return mac, nil
}
