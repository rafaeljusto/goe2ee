package kdf

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestHKDFRFC5869 validates HKDF-SHA256 against Test Case 1 from RFC 5869
// (Appendix A.1). DeriveKey uses an empty salt, so this exercises the
// underlying stdlib primitive directly with the vector's salt and info to
// confirm the hash and construction we rely on.
func TestHKDFRFC5869(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a"+
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf"+
		"34007208d5b887185865")

	got, err := hkdf.Key(sha256.New, ikm, salt, string(info), len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("HKDF output mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestDeriveKeyDeterministic ensures the same secret always produces the same
// key (client and server must agree) and that different secrets diverge.
func TestDeriveKeyDeterministic(t *testing.T) {
	secret := []byte("shared-secret-from-ecdh-exchange")

	a, err := DeriveKey(secret, Info, AESKeySize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKey(secret, Info, AESKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("DeriveKey is not deterministic for the same secret")
	}
	if len(a) != AESKeySize {
		t.Fatalf("expected %d-byte key but got %d", AESKeySize, len(a))
	}

	other, err := DeriveKey([]byte("a-different-shared-secret-value!!"), Info, AESKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, other) {
		t.Fatal("different secrets produced the same derived key")
	}
}

func TestDeriveKeyInvalidLength(t *testing.T) {
	if _, err := DeriveKey([]byte("secret"), Info, 0); err == nil {
		t.Fatal("expected an error for zero-length key")
	}
	if _, err := DeriveKey([]byte("secret"), Info, 255*32+1); err == nil {
		t.Fatal("expected an error for an oversized key")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}
