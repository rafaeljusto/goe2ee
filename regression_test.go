package goe2ee_test

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee/v2"
	"github.com/rafaeljusto/goe2ee/v2/key"
	"github.com/rafaeljusto/goe2ee/v2/protocol"
)

// TestHandshakeAllAlgorithms exercises a full handshake and encrypted
// round-trip for every supported server key algorithm. It is a regression test
// for the Ed25519 sign/verify mismatch, where the server signed with pure
// Ed25519 but the client verified with Ed25519ph, so Ed25519 handshakes could
// never succeed.
func TestHandshakeAllAlgorithms(t *testing.T) {
	algorithms := map[string]protocol.KeyAlgorithm{
		"RSA":     protocol.KeyAlgorithmRSA,
		"ECDSA":   protocol.KeyAlgorithmECDSA,
		"ED25519": protocol.KeyAlgorithmED25519,
	}

	for name, algorithm := range algorithms {
		algorithm := algorithm
		t.Run(name, func(t *testing.T) {
			serverKeyManager, err := key.ServerManagerGenerateOnTheFly(algorithm)
			if err != nil {
				t.Fatal(err)
			}

			server := goe2ee.NewServer(
				goe2ee.ServerHandlerFunc(reverseHandler),
				goe2ee.ServerWithKeyManager(serverKeyManager),
				goe2ee.ServerWithReadTimeout(5*time.Second),
				goe2ee.ServerWithWriteTimeout(5*time.Second),
				goe2ee.ServerWithLogger(log.New(io.Discard, "", 0)),
			)
			defer func() {
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			addr, err := server.StartTCP("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			client, err := goe2ee.DialTCP(addr.String(),
				goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol(addr.Network(), addr.String())),
				goe2ee.ClientWithReadTimeout(5*time.Second),
				goe2ee.ClientWithWriteTimeout(5*time.Second),
			)
			if err != nil {
				t.Fatalf("handshake failed for %s: %v", name, err)
			}
			defer func() {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if string(response) != "olleh" {
				t.Fatalf("expected 'olleh' but got '%s'", string(response))
			}
		})
	}
}

// TestHandshakeDefaultKeyManager verifies that a server created without an
// explicit key manager (which defaults to Ed25519 key generation) can complete
// a handshake. This is a regression test: the default configuration used to be
// unusable because of the Ed25519 signature bug.
func TestHandshakeDefaultKeyManager(t *testing.T) {
	server := goe2ee.NewServer(
		goe2ee.ServerHandlerFunc(reverseHandler),
		goe2ee.ServerWithReadTimeout(5*time.Second),
		goe2ee.ServerWithWriteTimeout(5*time.Second),
		goe2ee.ServerWithLogger(log.New(io.Discard, "", 0)),
	)
	defer func() {
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	addr, err := server.StartTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	client, err := goe2ee.DialTCP(addr.String(),
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol(addr.Network(), addr.String())),
		goe2ee.ClientWithReadTimeout(5*time.Second),
		goe2ee.ClientWithWriteTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("handshake with default (Ed25519) key manager failed: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "olleh" {
		t.Fatalf("expected 'olleh' but got '%s'", string(response))
	}
}
