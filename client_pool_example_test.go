package goe2ee_test

import (
	"log"

	"github.com/rafaeljusto/goe2ee"
	"github.com/rafaeljusto/goe2ee/key"
)

func ExampleClientPool() {
	hostport := "example.com:123"
	pool := goe2ee.NewClientPool(hostport, 10, 10,
		goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol("tcp", hostport)),
	)
	defer func() {
		if err := pool.Close(); err != nil {
			log.Println(err)
		}
	}()

	client, err := pool.Get()
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Println(err)
		}
	}()

	// do something with the client
}
