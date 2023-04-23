package key_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee"
	internaldnssec "github.com/rafaeljusto/goe2ee/internal/dns/dnssec"
	"github.com/rafaeljusto/goe2ee/key"
)

func TestClientFetcherDNSKEY_Fetch(t *testing.T) {
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		if err := serverListener.Close(); err != nil {
			t.Logf("failed to close listener: %v", err)
		}
	}()

	var handler func() string
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept") != "application/dns-json" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			response := struct {
				Answers []struct {
					Data string `json:"data"`
				} `json:"Answer"`
			}{
				Answers: []struct {
					Data string `json:"data"`
				}{{
					Data: handler(),
				}},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Logf("failed to write response: %v", err)
			}
		}),
	}

	go func() {
		if err := server.Serve(serverListener); !errors.Is(err, http.ErrServerClosed) {
			t.Logf("server closed with error: %v", err)
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			t.Logf("failed to close server: %v", err)
		}
	}()

	tests := []struct {
		name    string
		options []func(*key.ClientFetcherDNSKEYOptions)
		want    key.PublicKey
		wantErr bool
	}{{
		name: "it should validate a RSA key",
		want: func() key.PublicKey {
			privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
			if err != nil {
				t.Fatalf("failed to generate RSA private key: %v", err)
			}
			return key.PublicKey{PublicKey: &privateKey.PublicKey}
		}(),
	}, {
		name: "it should validate a ECDSA key",
		want: func() key.PublicKey {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA private key: %v", err)
			}
			return key.PublicKey{PublicKey: privateKey.Public()}
		}(),
	}, {
		name: "it should validate a Ed25519 key",
		want: func() key.PublicKey {
			publicKey, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate Ed25519 private key: %v", err)
			}
			return key.PublicKey{PublicKey: publicKey}
		}(),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler = func() string {
				dnskey, err := internaldnssec.BuildDNSKEY(tt.want.PublicKey)
				if err != nil {
					t.Fatalf("failed to build dnskey: %v", err)
				}
				return dnskey
			}
			fetcher := key.NewClientFetcherDNSKEY("http://"+serverListener.Addr().String(), tt.options...)
			got, err := fetcher.Fetch("example.com")
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Although crypto.PublicKey type is an empty interface for backwards
			// compatibility reasons, all public key types in the standard library
			// implement the following interface
			type equaler interface {
				Equal(crypto.PublicKey) bool
			}
			if (got.PublicKey == nil && tt.want.PublicKey != nil) ||
				(got.PublicKey != nil && !got.PublicKey.(equaler).Equal(tt.want.PublicKey)) {
				t.Errorf("unexpected result %#v, want %#v", got.PublicKey, tt.want.PublicKey)
			}
		})
	}
}

func TestClientFetcherTLS_Fetch(t *testing.T) {
	tests := []struct {
		name        string
		keyPair     func() (crypto.PrivateKey, crypto.PublicKey)
		certificate func(*x509.Certificate)
		wantErr     bool
	}{{
		name: "it should validate a RSA key",
		keyPair: func() (crypto.PrivateKey, crypto.PublicKey) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate RSA private key: %v", err)
			}
			return privateKey, privateKey.Public()
		},
	}, {
		name: "it should validate a ECDSA key",
		keyPair: func() (crypto.PrivateKey, crypto.PublicKey) {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA private key: %v", err)
			}
			return privateKey, privateKey.Public()
		},
	}, {
		name: "it should validate a Ed25519 key",
		keyPair: func() (crypto.PrivateKey, crypto.PublicKey) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate Ed25519 private key: %v", err)
			}
			return privateKey, publicKey
		},
	}, {
		name: "it should detect an invalid certificate",
		keyPair: func() (crypto.PrivateKey, crypto.PublicKey) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate RSA private key: %v", err)
			}
			return privateKey, privateKey.Public()
		},
		certificate: func(certificate *x509.Certificate) {
			certificate.NotBefore = time.Now().Add(time.Hour)
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				t.Fatalf("failed to generate serial number: %v", err)
			}

			privateKey, publicKey := tt.keyPair()
			keyUsage := x509.KeyUsageDigitalSignature
			if _, isRSA := privateKey.(*rsa.PrivateKey); isRSA {
				keyUsage |= x509.KeyUsageKeyEncipherment
			}
			keyUsage |= x509.KeyUsageCertSign

			template := x509.Certificate{
				SerialNumber:          serialNumber,
				NotBefore:             time.Now().Add(-1 * time.Hour),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:              keyUsage,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
				IsCA:                  true,
			}
			if tt.certificate != nil {
				tt.certificate(&template)
			}

			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
			if err != nil {
				t.Fatalf("failed to create certificate: %v", err)
			}

			certificate, err := x509.ParseCertificate(derBytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			caCertificatePool := x509.NewCertPool()
			caCertificatePool.AddCert(certificate)

			tlsConfig := &tls.Config{
				RootCAs:    caCertificatePool,
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  caCertificatePool,
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{derBytes},
						PrivateKey:  privateKey,
					},
				},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				},
			}

			server := http.Server{
				Addr:      "127.0.0.1:0",
				TLSConfig: tlsConfig,
				ErrorLog:  log.New(io.Discard, "", 0),
			}

			serverListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start server: %v", err)
			}
			defer func() {
				if err := serverListener.Close(); err != nil {
					t.Logf("failed to close listener: %v", err)
				}
			}()
			serverTLSListener := tls.NewListener(serverListener, tlsConfig)
			serverPort := serverTLSListener.Addr().(*net.TCPAddr).Port

			go func() {
				if err := server.Serve(serverTLSListener); !errors.Is(err, http.ErrServerClosed) {
					t.Logf("server closed with error: %v", err)
				}
			}()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if err := server.Shutdown(ctx); err != nil {
					t.Logf("failed to close server: %v", err)
				}
			}()

			fetcher := key.NewClientFetcherTLS(
				key.ClientFetcherTLSWithPort(uint64(serverPort)),
				key.ClientFetcherTLSWithRootCAs(caCertificatePool),
			)
			got, err := fetcher.Fetch("127.0.0.1")
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := publicKey
			if tt.wantErr {
				want = nil
			}
			// Although crypto.PublicKey type is an empty interface for backwards
			// compatibility reasons, all public key types in the standard library
			// implement the following interface
			type equaler interface {
				Equal(crypto.PublicKey) bool
			}
			if (got.PublicKey == nil && want != nil) || (got.PublicKey != nil && !got.PublicKey.(equaler).Equal(want)) {
				t.Errorf("unexpected result %#v, want %#v", got.PublicKey, want)
			}
		})
	}
}

func TestClientFetcherProtocol_Fetch(t *testing.T) {
	tests := []struct {
		name       string
		privateKey func() crypto.PrivateKey
		want       func(crypto.PrivateKey) key.PublicKey
		wantErr    bool
	}{{
		name: "it should retrieve a RSA key",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate RSA private key: %v", err)
			}
			return privateKey
		},
		want: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{PublicKey: privateKey.(*rsa.PrivateKey).Public()}
		},
	}, {
		name: "it should retrieve a ECDSA key",
		privateKey: func() crypto.PrivateKey {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA private key: %v", err)
			}
			return privateKey
		},
		want: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{PublicKey: privateKey.(*ecdsa.PrivateKey).Public()}
		},
	}, {
		name: "it should validate a Ed25519 key",
		privateKey: func() crypto.PrivateKey {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate Ed25519 private key: %v", err)
			}
			return privateKey
		},
		want: func(privateKey crypto.PrivateKey) key.PublicKey {
			return key.PublicKey{PublicKey: privateKey.(ed25519.PrivateKey).Public()}
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey := tt.privateKey()
			server := goe2ee.NewServer(nil,
				goe2ee.ServerWithKeyManager(key.NewServerManager(privateKey)),
				goe2ee.ServerWithLogger(log.New(io.Discard, "", 0)),
			)

			addr, err := server.StartTCP("127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start server: %v", err)
			}
			defer func() {
				if err := server.Close(); err != nil {
					t.Logf("failed to close server: %v", err)
				}
			}()

			fetcher := key.NewClientFetcherProtocol(addr.Network(), addr.String())
			publicKey, err := fetcher.Fetch("")
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Although crypto.PublicKey type is an empty interface for backwards
			// compatibility reasons, all public key types in the standard library
			// implement the following interface
			type equaler interface {
				Equal(crypto.PublicKey) bool
			}
			want := tt.want(privateKey)
			if (publicKey.PublicKey == nil && want.PublicKey != nil) ||
				(publicKey.PublicKey != nil && !publicKey.PublicKey.(equaler).Equal(want.PublicKey)) {
				t.Errorf("unexpected result %#v, want %#v", publicKey.PublicKey, want.PublicKey)
			}
		})
	}
}
