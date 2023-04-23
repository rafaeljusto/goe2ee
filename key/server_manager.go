package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"io"

	"github.com/rafaeljusto/goe2ee/protocol"
)

// ServerManager is a generic interface to manage the server's key-pair.
type ServerManager interface {
	FetchKey() (protocol.KeyAlgorithm, PublicKey, error)
	Sign(crypto.Hash, []byte) ([]byte, error)
}

// ServerManagerInMemory loads the private key and stores it in-memory.
type ServerManagerInMemory struct {
	privateKey crypto.PrivateKey
}

// NewServerManager creates a new server manager with the given private key.
func NewServerManager(privateKey crypto.PrivateKey) *ServerManagerInMemory {
	return &ServerManagerInMemory{
		privateKey: privateKey,
	}
}

// ServerManagerParsePEM parses a PEM encoded private key, unencrypting the
// private key in PKCS #8, ASN.1 DER form.
func ServerManagerParsePEM(r io.Reader) (*ServerManagerInMemory, error) {
	pubPEMData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded private key: %w", err)
	}

	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, fmt.Errorf("unsupported private key type '%T'", privateKey)
	}

	return &ServerManagerInMemory{
		privateKey: privateKey,
	}, nil
}

// ServerManagerGenerateOnTheFly generates a new key-pair on the fly. This is
// not recommended for production use.
func ServerManagerGenerateOnTheFly(algorithm protocol.KeyAlgorithm) (*ServerManagerInMemory, error) {
	var privateKey crypto.PrivateKey
	var err error
	switch algorithm {
	case protocol.KeyAlgorithmRSA:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case protocol.KeyAlgorithmECDSA:
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case protocol.KeyAlgorithmED25519:
		privateKey, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported algorithm '%s'", algorithm)
	}
	if err != nil {
		return nil, err
	}
	return &ServerManagerInMemory{
		privateKey: privateKey,
	}, nil
}

// FetchKey returns the server's public key.
func (s *ServerManagerInMemory) FetchKey() (protocol.KeyAlgorithm, PublicKey, error) {
	var algorithm protocol.KeyAlgorithm
	var publicKey crypto.PublicKey
	switch privateKey := s.privateKey.(type) {
	case *rsa.PrivateKey:
		algorithm = protocol.KeyAlgorithmRSA
		publicKey = privateKey.Public()
	case *ecdsa.PrivateKey:
		algorithm = protocol.KeyAlgorithmECDSA
		publicKey = privateKey.Public()
	case ed25519.PrivateKey:
		algorithm = protocol.KeyAlgorithmED25519
		publicKey = privateKey.Public()
	default:
		return 0, PublicKey{}, fmt.Errorf("unsupported private key type '%T'", privateKey)
	}
	return algorithm, PublicKey{PublicKey: publicKey}, nil
}

// Sign signs the content using the server's private key.
func (s *ServerManagerInMemory) Sign(hashType crypto.Hash, content []byte) ([]byte, error) {
	var h hash.Hash
	switch hashType {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash type '%s'", hashType)
	}
	if _, err := h.Write(content); err != nil {
		return nil, err
	}

	var err error
	var signature []byte
	switch privateKey := s.privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, hashType, h.Sum(nil))
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, h.Sum(nil))
	case ed25519.PrivateKey:
		signature, err = ed25519.Sign(privateKey, h.Sum(nil)), nil
	default:
		return nil, fmt.Errorf("unsupported private key type '%T'", privateKey)
	}
	return signature, err
}
