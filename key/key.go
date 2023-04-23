package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// PublicKey adds some extra functionality to the crypto.PublicKey interface.
type PublicKey struct {
	crypto.PublicKey
}

// VerifySignature verifies the signature of the content using the public key.
func (p PublicKey) VerifySignature(hashType crypto.Hash, content, signature []byte) (bool, error) {
	var hash hash.Hash
	switch hashType {
	case crypto.SHA1:
		hash = sha1.New()
	case crypto.SHA256:
		hash = sha256.New()
	case crypto.SHA384:
		hash = sha512.New384()
	case crypto.SHA512:
		hash = sha512.New()
	default:
		return false, fmt.Errorf("unsupported hash type '%s'", hashType)
	}

	if _, err := hash.Write(content); err != nil {
		return false, fmt.Errorf("failed to hash message: %w", err)
	}
	hashedMessage := hash.Sum(nil)

	var valid bool
	switch publicKey := p.PublicKey.(type) {
	case *rsa.PublicKey:
		valid = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashedMessage, signature) == nil
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(publicKey, hashedMessage, signature)
	case ed25519.PublicKey:
		valid = ed25519.VerifyWithOptions(publicKey, hashedMessage, signature, &ed25519.Options{
			Hash: crypto.SHA512,
		}) == nil
	default:
		return false, fmt.Errorf("public key %T not supported", publicKey)
	}
	return valid, nil
}
