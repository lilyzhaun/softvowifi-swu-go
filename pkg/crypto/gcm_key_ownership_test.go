package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestAESGCMDoesNotOverwriteAdjacentDerivedKeys(t *testing.T) {
	for _, operation := range []string{"encrypt", "decrypt", "bad tag"} {
		t.Run(operation, func(t *testing.T) {
			// Production IKE/Child KEYMAT splits share backing storage. SK_e's
			// trailing salt must not overwrite the following directional keys.
			material := bytes.Repeat([]byte{0x22}, 64)
			key := material[:20]
			before := bytes.Clone(material)
			iv := bytes.Repeat([]byte{0x63}, 8)
			aad := []byte("synthetic IKE header")
			plain := []byte("synthetic plaintext")
			block, err := aes.NewCipher(key[:16])
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			nonce := append(bytes.Clone(key[16:20]), iv...)
			sealed := gcm.Seal(nil, nonce, plain, aad)
			enc, err := GetEncrypterWithKeyLen(20, 128)
			if err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "encrypt":
				got, err := enc.Encrypt(plain, key, iv, aad)
				if err != nil || !bytes.Equal(got, sealed) {
					t.Fatal("standard GCM ciphertext differs")
				}
			case "decrypt":
				got, err := enc.Decrypt(sealed, key, iv, aad)
				if err != nil || !bytes.Equal(got, plain) {
					t.Fatal("standard GCM peer cannot be decrypted")
				}
			case "bad tag":
				sealed[len(sealed)-1] ^= 1
				if _, err := enc.Decrypt(sealed, key, iv, aad); err == nil {
					t.Fatal("invalid tag accepted")
				}
			}
			if !bytes.Equal(material, before) {
				t.Fatal("nonce construction overwrote adjacent derived keys")
			}
		})
	}
}
