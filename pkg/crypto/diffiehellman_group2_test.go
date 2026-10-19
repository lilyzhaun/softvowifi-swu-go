package crypto

import (
	"bytes"
	"math/big"
	"testing"
)

const rfc2409Group2PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

func TestNewDiffieHellmanGroup2RFC2409DeterministicAndFixedWidth(t *testing.T) {
	wantP, ok := new(big.Int).SetString(rfc2409Group2PrimeHex, 16)
	if !ok {
		t.Fatal("invalid RFC 2409 group 2 prime constant")
	}

	dh, err := NewDiffieHellman(2)
	if err != nil {
		t.Fatalf("NewDiffieHellman(2) failed: %v", err)
	}
	if dh.Group != 2 || dh.P == nil || dh.G == nil {
		t.Fatalf("unexpected DH group 2 struct: %+v", dh)
	}
	if dh.P.Cmp(wantP) != 0 || dh.P.BitLen() != 1024 || dh.G.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("DH group 2 parameters mismatch: bitLen=%d G=%v", dh.P.BitLen(), dh.G)
	}

	if err := dh.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(dh.PublicKeyBytes()) != 128 {
		t.Fatalf("group 2 PublicKeyBytes length = %d, want 128", len(dh.PublicKeyBytes()))
	}

	// Deterministic small-value check to verify fixed 128-byte left zero-padding
	// on both PublicKeyBytes and ComputeSharedSecret.
	dhSmall, err := NewDiffieHellman(2)
	if err != nil {
		t.Fatalf("NewDiffieHellman(2) failed: %v", err)
	}
	dhSmall.PrivateKey = big.NewInt(2)
	dhSmall.PublicKey = new(big.Int).Exp(dhSmall.G, dhSmall.PrivateKey, dhSmall.P)
	pubSmall := dhSmall.PublicKeyBytes()
	wantPubSmall := make([]byte, 128)
	wantPubSmall[127] = 4
	if !bytes.Equal(pubSmall, wantPubSmall) {
		t.Fatalf("padded public key mismatch: got len=%d last=%d", len(pubSmall), pubSmall[len(pubSmall)-1])
	}

	peerSmall := make([]byte, 128)
	peerSmall[127] = 2
	sharedSmall, err := dhSmall.ComputeSharedSecret(peerSmall)
	if err != nil {
		t.Fatalf("ComputeSharedSecret(small valid peer) failed: %v", err)
	}
	if !bytes.Equal(sharedSmall, wantPubSmall) {
		t.Fatalf("padded shared secret mismatch: got len=%d", len(sharedSmall))
	}

	// Deterministic full-width exponentiation check against independent math/big.
	privA := new(big.Int).SetBytes(bytes.Repeat([]byte{0x35, 0x79, 0xa1, 0xc3}, 31))
	privB := new(big.Int).SetBytes(bytes.Repeat([]byte{0x24, 0x68, 0xb2, 0xd4}, 31))

	dhA, err := NewDiffieHellman(2)
	if err != nil {
		t.Fatal(err)
	}
	dhA.PrivateKey = privA
	dhA.PublicKey = new(big.Int).Exp(dhA.G, dhA.PrivateKey, dhA.P)

	dhB, err := NewDiffieHellman(2)
	if err != nil {
		t.Fatal(err)
	}
	dhB.PrivateKey = privB
	dhB.PublicKey = new(big.Int).Exp(dhB.G, dhB.PrivateKey, dhB.P)

	secA, err := dhA.ComputeSharedSecret(dhB.PublicKeyBytes())
	if err != nil {
		t.Fatalf("dhA.ComputeSharedSecret failed: %v", err)
	}
	secB, err := dhB.ComputeSharedSecret(dhA.PublicKeyBytes())
	if err != nil {
		t.Fatalf("dhB.ComputeSharedSecret failed: %v", err)
	}

	indepPubB := new(big.Int).Exp(big.NewInt(2), privB, wantP)
	indepSecret := new(big.Int).Exp(indepPubB, privA, wantP).FillBytes(make([]byte, 128))
	if !bytes.Equal(secA, indepSecret) || !bytes.Equal(secB, indepSecret) {
		t.Fatal("group 2 shared secret does not match independent RFC 2409 math/big calculation")
	}
}

func TestDiffieHellmanGroup2And14RejectInvalidPeerPublicKeys(t *testing.T) {
	for _, unsupported := range []uint16{0, 1, 5, 15, 16, 19, 20, 21, 99} {
		if _, err := NewDiffieHellman(unsupported); err == nil {
			t.Fatalf("NewDiffieHellman(%d) succeeded for unsupported group", unsupported)
		}
	}

	for _, tc := range []struct {
		group      uint16
		width      int
		otherWidth int
	}{
		{group: 2, width: 128, otherWidth: 256},
		{group: 14, width: 256, otherWidth: 128},
	} {
		dh, err := NewDiffieHellman(tc.group)
		if err != nil {
			t.Fatalf("NewDiffieHellman(%d) failed: %v", tc.group, err)
		}
		if err := dh.GenerateKey(); err != nil {
			t.Fatalf("GenerateKey(%d) failed: %v", tc.group, err)
		}

		shortValidValue := make([]byte, tc.width-1)
		shortValidValue[len(shortValidValue)-1] = 2
		longValidValue := make([]byte, tc.width+1)
		longValidValue[len(longValidValue)-1] = 2
		otherGroupWidthValue := make([]byte, tc.otherWidth)
		otherGroupWidthValue[len(otherGroupWidthValue)-1] = 2

		oneFixed := make([]byte, tc.width)
		oneFixed[tc.width-1] = 1
		pMinusOne := new(big.Int).Sub(dh.P, big.NewInt(1)).FillBytes(make([]byte, tc.width))
		pExact := dh.P.FillBytes(make([]byte, tc.width))
		allOnes := bytes.Repeat([]byte{0xff}, tc.width)

		badKeys := map[string][]byte{
			"nil":               nil,
			"empty":             {},
			"single_byte_two":   {2},
			"short_width":       shortValidValue,
			"long_width":        longValidValue,
			"other_group_width": otherGroupWidthValue,
			"zero":              make([]byte, tc.width),
			"one":               oneFixed,
			"p_minus_one":       pMinusOne,
			"p_exact":           pExact,
			"all_ones":          allOnes,
		}

		for name, bad := range badKeys {
			dh.SharedKey = nil
			if _, err := dh.ComputeSharedSecret(bad); err == nil {
				t.Fatalf("group %d accepted invalid peer public key %q (len=%d)", tc.group, name, len(bad))
			}
			if dh.SharedKey != nil {
				t.Fatalf("group %d retained SharedKey after rejecting %q", tc.group, name)
			}
		}
	}
}
