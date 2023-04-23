package goe2ee_test

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee"
	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
)

func BenchmarkServer_tcpHandshake(b *testing.B) {
	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmRSA)
	if err != nil {
		b.Fatal(err)
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
			b.Fatal(err)
		}
	}()

	addr, err := server.StartTCP("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		client, err := goe2ee.DialTCP(addr.String(),
			goe2ee.ClientWithKeyFetcher(key.NewClientFetcherCache(
				key.NewClientFetcherProtocol(addr.Network(), addr.String())),
			),
			goe2ee.ClientWithReadTimeout(5*time.Second),
			goe2ee.ClientWithWriteTimeout(5*time.Second),
		)
		if err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServer_tcpDailyWork(b *testing.B) {
	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmRSA)
	if err != nil {
		b.Fatal(err)
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
			b.Fatal(err)
		}
	}()

	addr, err := server.StartTCP("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	client, err := goe2ee.DialTCP(addr.String(),
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherCache(key.NewClientFetcherProtocol(addr.Network(), addr.String()))),
		goe2ee.ClientWithReadTimeout(5*time.Second),
		goe2ee.ClientWithWriteTimeout(5*time.Second),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}()

	var buf [5]byte
	for n := 0; n < b.N; n++ {
		if _, err := client.Write([]byte("hello")); err != nil {
			b.Fatal(err)
		}
		if _, err := client.Read(buf[:]); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func BenchmarkServer_udpHandshake(b *testing.B) {
	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmRSA)
	if err != nil {
		b.Fatal(err)
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
			b.Fatal(err)
		}
	}()

	addr, err := server.StartUDP("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		client, err := goe2ee.DialUDP(addr.String(),
			goe2ee.ClientWithKeyFetcher(key.NewClientFetcherCache(key.NewClientFetcherProtocol("udp", addr.String()))),
			goe2ee.ClientWithReadTimeout(5*time.Second),
			goe2ee.ClientWithWriteTimeout(5*time.Second),
		)
		if err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServer_udpDailyWork(b *testing.B) {
	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmRSA)
	if err != nil {
		b.Fatal(err)
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
			b.Fatal(err)
		}
	}()

	addr, err := server.StartUDP("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	client, err := goe2ee.DialUDP(addr.String(),
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherCache(key.NewClientFetcherProtocol("udp", addr.String()))),
		goe2ee.ClientWithReadTimeout(5*time.Second),
		goe2ee.ClientWithWriteTimeout(5*time.Second),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}()

	var buf [5]byte
	for n := 0; n < b.N; n++ {
		if _, err := client.Write([]byte("hello")); err != nil {
			b.Fatal(err)
		}
		if _, err := client.Read(buf[:]); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
