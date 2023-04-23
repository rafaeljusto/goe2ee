package goe2ee_test

import (
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee"
	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
)

func TestClientPool(t *testing.T) {
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

	time.Sleep(100 * time.Millisecond)

	addr, err := server.StartTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	pool := goe2ee.NewClientPool(addr.String(), 10, 10,
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol(addr.Network(), addr.String())),
		goe2ee.ClientWithReadTimeout(5*time.Second),
		goe2ee.ClientWithWriteTimeout(5*time.Second),
	)
	defer func() {
		if err := pool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	numberOfClients := 100
	var wg sync.WaitGroup
	wg.Add(numberOfClients)
	for i := 0; i < numberOfClients; i++ {
		go func(t *testing.T, wg *sync.WaitGroup) {
			defer wg.Done()

			client, err := pool.Get()
			if err != nil {
				t.Error(err)
				return
			}

			if _, err := client.Write([]byte("hello")); err != nil {
				t.Error(err)
				return
			}
			response, err := io.ReadAll(client)
			if err != nil {
				t.Error(err)
				return
			}
			if string(response) != "olleh" {
				t.Errorf("expected 'olleh' but got '%s'", string(response))
			}

			if err := client.Close(); err != nil {
				t.Error(err)
				return
			}
		}(t, &wg)
	}
	wg.Wait()
}
