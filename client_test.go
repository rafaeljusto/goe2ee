package goe2ee_test

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee"
	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
)

func TestDialTCP(t *testing.T) {
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

	client, err := goe2ee.DialTCP(addr.String(),
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol(addr.Network(), addr.String())),
		goe2ee.ClientWithReadTimeout(5*time.Second),
		goe2ee.ClientWithWriteTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
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

func TestDialUDP(t *testing.T) {
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

	addr, err := server.StartUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	client, err := goe2ee.DialUDP(addr.String(),
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol("udp", addr.String())),
		goe2ee.ClientWithReadTimeout(5*time.Second),
		goe2ee.ClientWithWriteTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	response := make([]byte, 5)
	n, err := io.ReadFull(client, response)
	if err != nil {
		t.Fatal(err)
	} else if n != 5 {
		t.Fatalf("expected 5 bytes but got %d", n)
	}
	if string(response) != "olleh" {
		t.Fatalf("expected 'olleh' but got '%s'", string(response))
	}
}

func reverseHandler(w io.Writer, r io.Reader, _ net.Addr) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	runes := []rune(string(content))
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	_, err = w.Write([]byte(string(runes)))
	return err
}
