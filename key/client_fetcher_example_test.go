package key_test

import (
	"log"

	"github.com/rafaeljusto/goe2ee"
	"github.com/rafaeljusto/goe2ee/key"
)

func ExampleClientFetcherDNSKEY_Fetch() {
	hostport := "example.com:123"
	client, err := goe2ee.DialTCP(hostport,
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherDNSKEY(key.GoogleDNSProvider)),
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()
}

func ExampleClientFetcherTLS_Fetch() {
	hostport := "example.com:123"
	client, err := goe2ee.DialTCP(hostport,
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherTLS()),
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()
}

func ExampleClientFetcherProtocol_Fetch() {
	hostport := "example.com:123"
	client, err := goe2ee.DialTCP(hostport,
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol("tcp", hostport)),
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("failed to close client: %v", err)
		}
	}()
}
