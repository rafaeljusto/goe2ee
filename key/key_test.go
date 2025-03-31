package key_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/rafaeljusto/goe2ee/key"
)

func TestPublicKey_VerifySignature(t *testing.T) {
	tests := []struct {
		name       string
		privateKey crypto.PrivateKey
		publicKey  func(crypto.PrivateKey) key.PublicKey
		hashType   crypto.Hash
		content    []byte
		signature  func(crypto.PrivateKey) []byte
		want       bool
		wantErr    bool
	}{{
		name: "it should validate a RSA key",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate RSA key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: &privateKey.(*rsa.PrivateKey).PublicKey,
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(privateKey crypto.PrivateKey) []byte {
			hash := crypto.SHA512.New()
			if _, err := hash.Write([]byte("hello world")); err != nil {
				t.Fatalf("failed to hash message: %v", err)
			}
			rsaPrivateKey := privateKey.(*rsa.PrivateKey)
			signature, err := rsaPrivateKey.Sign(rand.Reader, hash.Sum(nil), crypto.SHA512)
			if err != nil {
				t.Fatalf("failed to sign message: %v", err)
			}
			return signature
		},
		want:    true,
		wantErr: false,
	}, {
		name: "it should detect a RSA signature issue",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate RSA key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: &privateKey.(*rsa.PrivateKey).PublicKey,
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(crypto.PrivateKey) []byte {
			return []byte("invalid signature")
		},
		want:    false,
		wantErr: false,
	}, {
		name: "it should validate a ECDSA key",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: privateKey.(*ecdsa.PrivateKey).Public(),
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(privateKey crypto.PrivateKey) []byte {
			hash := crypto.SHA512.New()
			if _, err := hash.Write([]byte("hello world")); err != nil {
				t.Fatalf("failed to hash message: %v", err)
			}
			ecdsaPrivateKey := privateKey.(*ecdsa.PrivateKey)
			signature, err := ecdsaPrivateKey.Sign(rand.Reader, hash.Sum(nil), crypto.SHA512)
			if err != nil {
				t.Fatalf("failed to sign message: %v", err)
			}
			return signature
		},
		want:    true,
		wantErr: false,
	}, {
		name: "it should detect a ECDSA signature issue",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: privateKey.(*ecdsa.PrivateKey).Public(),
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(crypto.PrivateKey) []byte {
			return []byte("invalid signature")
		},
		want:    false,
		wantErr: false,
	}, {
		name: "it should validate a ED25519 key",
		privateKey: func() crypto.PrivateKey {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ED25519 key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: privateKey.(ed25519.PrivateKey).Public(),
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(privateKey crypto.PrivateKey) []byte {
			hash := crypto.SHA512.New()
			if _, err := hash.Write([]byte("hello world")); err != nil {
				t.Fatalf("failed to hash message: %v", err)
			}
			ed25519PrivateKey := privateKey.(ed25519.PrivateKey)
			signature, err := ed25519PrivateKey.Sign(rand.Reader, hash.Sum(nil), crypto.SHA512)
			if err != nil {
				t.Fatalf("failed to sign message: %v", err)
			}
			return signature
		},
		want:    true,
		wantErr: false,
	}, {
		name: "it should detect a ED25519 signature issue",
		privateKey: func() crypto.PrivateKey {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ED25519 key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: privateKey.(ed25519.PrivateKey).Public(),
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(crypto.PrivateKey) []byte {
			return []byte("invalid signature")
		},
		want:    false,
		wantErr: false,
	}, {
		name: "it should detect an invalid key type",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDH key: %v", err)
			}
			return privateKey
		}(),
		publicKey: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{
				PublicKey: privateKey.(*ecdh.PrivateKey).Public(),
			}
		},
		hashType: crypto.SHA512,
		content:  []byte("hello world"),
		signature: func(crypto.PrivateKey) []byte {
			return []byte("something")
		},
		want:    false,
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey := tt.publicKey(tt.privateKey)
			got, err := publicKey.VerifySignature(tt.hashType, tt.content, tt.signature(tt.privateKey))
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("unexpected result %v, want %v", got, tt.want)
			}
		})
	}
}
