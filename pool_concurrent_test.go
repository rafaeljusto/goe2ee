package goe2ee_test

import (
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee/v2"
	"github.com/rafaeljusto/goe2ee/v2/key"
	"github.com/rafaeljusto/goe2ee/v2/protocol"
)

// TestClientPoolConcurrentRoundTrips drives many concurrent round-trips through
// a pool that shares a single secret across its connections. It is a regression
// test for the counter-based nonce scheme: the send counter must be shared and
// incremented atomically across pooled connections, and the server's replay
// window must accept the resulting (reordered) counters. Run with -race to also
// catch data races on the shared counter.
func TestClientPoolConcurrentRoundTrips(t *testing.T) {
	serverKeyManager, err := key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmRSA)
	if err != nil {
		t.Fatal(err)
	}

	server := goe2ee.NewServer(
		goe2ee.ServerHandlerFunc(reverseHandler),
		goe2ee.ServerWithKeyManager(serverKeyManager),
		goe2ee.ServerWithReadTimeout(10*time.Second),
		goe2ee.ServerWithWriteTimeout(10*time.Second),
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

	pool := goe2ee.NewClientPool(addr.String(), 8, 8,
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol(addr.Network(), addr.String())),
		goe2ee.ClientWithReadTimeout(10*time.Second),
		goe2ee.ClientWithWriteTimeout(10*time.Second),
	)
	defer func() {
		if err := pool.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	const workers = 8
	const perWorker = 25

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				client, err := pool.Get()
				if err != nil {
					errs <- err
					return
				}
				if _, err := client.Write([]byte("hello")); err != nil {
					errs <- err
					_ = client.Close()
					return
				}
				response := make([]byte, 5)
				if _, err := io.ReadFull(client, response); err != nil {
					errs <- err
					_ = client.Close()
					return
				}
				if string(response) != "olleh" {
					errs <- errUnexpected(string(response))
					_ = client.Close()
					return
				}
				if err := client.Close(); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

type unexpectedResponseError string

func (e unexpectedResponseError) Error() string {
	return "unexpected response: " + string(e)
}

func errUnexpected(got string) error {
	return unexpectedResponseError(got)
}
