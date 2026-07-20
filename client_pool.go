package goe2ee

import (
	"sync"

	"github.com/rafaeljusto/goe2ee/v2/protocol"
)

// ClientPool is a pool of clients. It is useful when you need to connect to the
// same host multiple times.
type ClientPool struct {
	hostport        string
	poolMutex       sync.Mutex
	clientOptions   []func(*ClientOptions)
	idleClients     []*Client
	numberOfClients int64
	maxIdleClients  int64
	maxOpenClients  int64
	waitingClients  chan *Client
	session         *clientSession
}

// NewClientPool creates a new client pool.
func NewClientPool(
	hostport string,
	maxIdleClients int64,
	maxOpenClients int64,
	optFunc ...func(*ClientOptions),
) ClientPool {
	return ClientPool{
		hostport:       hostport,
		clientOptions:  optFunc,
		waitingClients: make(chan *Client),
		maxIdleClients: maxIdleClients,
		maxOpenClients: maxOpenClients,
	}
}

// Get retrieves a client from the pool. If there is no idle client available, a
// new one will be created. If the maximum number of clients is reached, it will
// wait until a client is available.
func (cp *ClientPool) Get() (*Client, error) {
	cp.poolMutex.Lock()

	for len(cp.idleClients) > 0 {
		client := cp.idleClients[0]
		cp.idleClients = cp.idleClients[1:]
		cp.poolMutex.Unlock()
		if cp.testOnBorrow(client) {
			return client, nil
		}
		_ = client.Close() // ignoring error as the connected is already busted
		cp.poolMutex.Lock()
		cp.numberOfClients--
	}

	if cp.numberOfClients >= cp.maxOpenClients {
		cp.poolMutex.Unlock()
		client := <-cp.waitingClients
		if cp.testOnBorrow(client) {
			return client, nil
		}
		_ = client.Close() // ignoring error as the connected is already busted
		cp.poolMutex.Lock()
		cp.numberOfClients--
	}

	var client *Client
	var err error

	if cp.session == nil {
		client, err = DialTCP(cp.hostport, cp.clientOptions...)
		if err != nil {
			cp.poolMutex.Unlock()
			return nil, err
		}
		client.pool = cp

		// Share the established session (secret, id, and send counter) so every
		// pooled connection increments the same counter and never reuses a nonce.
		cp.session = client.session

	} else {
		client, err = dialTCP(cp.hostport, cp.clientOptions...)
		if err != nil {
			cp.poolMutex.Unlock()
			return nil, err
		}
		client.pool = cp

		client.session = cp.session
	}

	cp.numberOfClients++
	cp.poolMutex.Unlock()
	return client, nil
}

func (cp *ClientPool) put(client *Client) error {
	cp.poolMutex.Lock()
	defer cp.poolMutex.Unlock()

	select {
	case cp.waitingClients <- client:
		return nil
	default:
	}

	if len(cp.idleClients) >= int(cp.maxIdleClients) {
		cp.numberOfClients--
		return client.close()
	}

	cp.idleClients = append(cp.idleClients, client)
	return nil
}

// Close closes all the clients in the pool.
func (cp *ClientPool) Close() error {
	cp.poolMutex.Lock()
	defer cp.poolMutex.Unlock()

	for _, client := range cp.idleClients {
		if err := client.close(); err != nil {
			return err
		}
	}

	cp.idleClients = nil
	cp.numberOfClients = 0
	cp.session = nil
	close(cp.waitingClients)

	return nil
}

func (cp *ClientPool) testOnBorrow(client *Client) bool {
	helloRequest := protocol.NewHelloRequest()
	n, err := client.conn.Write(helloRequest.Bytes())
	if err != nil || n != len(helloRequest.Bytes()) {
		return false
	}
	commonResponse, err := protocol.ParseResponseCommon(client.conn)
	if err != nil || !commonResponse.Success() {
		return false
	}
	return true
}
