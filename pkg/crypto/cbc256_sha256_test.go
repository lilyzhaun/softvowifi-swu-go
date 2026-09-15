package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func Test_CBC256MatchesNIST_whenKnownBlock(t *testing.T) {
	decode := func(value string) []byte {
		raw, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	key := decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := decode("000102030405060708090a0b0c0d0e0f")
	plain := decode("6bc1bee22e409f96e93d7e117393172a")
	want := decode("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
	algorithm, err := GetEncrypterWithKeyLen(12, 256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := algorithm.Encrypt(plain, key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("CBC256 known answer: %x", got)
	}
	decoded, err := algorithm.Decrypt(want, key, iv, nil)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("CBC256 decrypt: %x, %v", decoded, err)
	}
}

func Test_SHA256MatchesRFC4231_whenPRFAndIntegrity(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	input := []byte("Hi There")
	want, err := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	if err != nil {
		t.Fatal(err)
	}
	prf, err := GetPRF(5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := prf.Compute(key, input)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("PRF known answer: %x, %v", got, err)
	}
	integrity, err := GetIntegrityAlgorithm(12)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(integrity.Compute(key, input), want[:16]) {
		t.Fatal("ICV known answer mismatch")
	}
	want[0] ^= 1
	if integrity.Verify(key, input, want[:16]) {
		t.Fatal("accepted tampered ICV")
	}
}
