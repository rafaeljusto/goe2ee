package goe2ee_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee/v2"
	"github.com/rafaeljusto/goe2ee/v2/internal/kdf"
	"github.com/rafaeljusto/goe2ee/v2/key"
	"github.com/rafaeljusto/goe2ee/v2/protocol"
)

// TestProcessReplayRejected performs the handshake manually so it can resend a
// byte-for-byte identical Process request. The server must accept it once and
// reject the replay.
func TestProcessReplayRejected(t *testing.T) {
	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmRSA)
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

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// --- handshake ---
	clientPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := [16]byte{0x01, 0x02, 0x03, 0x04}

	if _, err := conn.Write(protocol.NewSetupRequest(id, clientPrivateKey.PublicKey()).Bytes()); err != nil {
		t.Fatal(err)
	}
	responseCommon, err := protocol.ParseResponseCommon(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !responseCommon.Success() {
		t.Fatal("setup response was not successful")
	}
	setupResponse, err := protocol.ParseSetupResponse(responseCommon, conn)
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := clientPrivateKey.ECDH(setupResponse.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	// --- build a Process request (counter = 1) ---
	gcm := newTestGCM(t, sharedSecret)
	nonce := protocol.Nonce(protocol.DirectionClientToServer, 1, gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, []byte("hello"), nil)
	requestBytes := protocol.NewProcessRequest(id, 1, ciphertext).Bytes()

	// First send: must succeed.
	if _, err := conn.Write(requestBytes); err != nil {
		t.Fatal(err)
	}
	responseCommon, err = protocol.ParseResponseCommon(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !responseCommon.Success() {
		errResponse, _ := protocol.ParseErrorResponse(conn, responseCommon)
		t.Fatalf("first request rejected: %s (code %d)", errResponse.ErrorMessage(), errResponse.ErrorCode())
	}
	if _, err := protocol.ParseProcessResponse(conn, responseCommon); err != nil {
		t.Fatal(err)
	}

	// Replay the exact same bytes: must be rejected as a replay.
	if _, err := conn.Write(requestBytes); err != nil {
		t.Fatal(err)
	}
	responseCommon, err = protocol.ParseResponseCommon(conn)
	if err != nil {
		t.Fatal(err)
	}
	if responseCommon.Success() {
		t.Fatal("replayed request was accepted, expected a replay error")
	}
	errResponse, err := protocol.ParseErrorResponse(conn, responseCommon)
	if err != nil {
		t.Fatal(err)
	}
	if errResponse.ErrorCode() != protocol.ErrorCodeReplayDetected {
		t.Fatalf("expected replay error code %d, got %d (%s)",
			protocol.ErrorCodeReplayDetected, errResponse.ErrorCode(), errResponse.ErrorMessage())
	}
}

func newTestGCM(t *testing.T, secret []byte) cipher.AEAD {
	t.Helper()
	aesKey, err := kdf.DeriveKey(secret, kdf.Info, kdf.AESKeySize)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}
