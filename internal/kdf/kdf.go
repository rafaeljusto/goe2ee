// Package kdf provides key derivation used to turn a raw Diffie-Hellman shared
// secret into a symmetric encryption key. The raw output of an ECDH exchange is
// not uniformly distributed and must not be used directly as a cipher key, so
// it is run through HKDF (RFC 5869) first.
package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// Info is the context/application-specific label used for domain separation
// when deriving the symmetric key. Changing it changes every derived key, so it
// must stay stable for client and server to agree on the same key.
var Info = []byte("goe2ee/v1 aes-256-gcm")

// AESKeySize is the size in bytes of the derived AES-256 key.
const AESKeySize = 32

// DeriveKey derives a key of the given length from a high-entropy secret (such
// as an ECDH shared secret) using HKDF-SHA256 with an empty salt. It returns an
// error if the requested length is invalid for the hash.
func DeriveKey(secret, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid derived key length %d", length)
	}
	key, err := hkdf.Key(sha256.New, secret, nil, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return key, nil
}
