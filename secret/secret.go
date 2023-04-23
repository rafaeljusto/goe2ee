// Package secret provides a simple interface to store and load secrets. It also
// provides some built-in implementations.
package secret

import (
	"sync"
	"time"
)

// Manager is the interface that wraps the basic operations to store and load a
// secret.
type Manager interface {
	Store(id string, secret []byte) error
	Load(id string) ([]byte, bool)
}

// InMemoryManager implements the Manager interface.
var _ Manager = (*InMemoryManager)(nil)

// InMemoryManagerOptions is used to configure the InMemoryManager.
type InMemoryManagerOptions struct {
	gcTicker time.Duration
	ttl      time.Duration
}

// InMemoryManagerWithGCTicker sets the amount of time that the garbage
// collector will run. By default, the garbage collector will run every minute.
func InMemoryManagerWithGCTicker(ticker time.Duration) func(*InMemoryManagerOptions) {
	return func(o *InMemoryManagerOptions) {
		o.gcTicker = ticker
	}
}

// InMemoryManagerWithTTL sets the amount of time that the secret will be stored
// after it is idle (not accessed anymore). By default, the secret will be
// stored for 15 minutes.
func InMemoryManagerWithTTL(ttl time.Duration) func(*InMemoryManagerOptions) {
	return func(o *InMemoryManagerOptions) {
		o.ttl = ttl
	}
}

// InMemoryManager is a manager that stores the secrets in memory.
type InMemoryManager struct {
	secrets sync.Map
}

// NewInMemoryManager creates a new InMemoryManager.
func NewInMemoryManager(optFuncs ...func(*InMemoryManagerOptions)) *InMemoryManager {
	options := &InMemoryManagerOptions{
		gcTicker: time.Minute,
		ttl:      15 * time.Minute,
	}
	for _, optFunc := range optFuncs {
		optFunc(options)
	}
	m := &InMemoryManager{}
	if options.ttl > 0 {
		go func() {
			timeTicker := time.NewTicker(options.gcTicker)
			defer timeTicker.Stop()

			for range timeTicker.C {
				m.secrets.Range(func(key, value interface{}) bool {
					secretItem := value.(struct {
						secret       []byte
						lastAccessAt time.Time
					})
					if time.Since(secretItem.lastAccessAt) > options.ttl {
						m.secrets.Delete(key)
					}
					return true
				})
			}
		}()
	}
	return m
}

// Store stores the secret in memory.
func (m *InMemoryManager) Store(id string, secret []byte) error {
	m.secrets.Store(id, struct {
		secret       []byte
		lastAccessAt time.Time
	}{
		secret:       secret,
		lastAccessAt: time.Now(),
	})
	return nil
}

// Load loads the secret from memory.
func (m *InMemoryManager) Load(id string) ([]byte, bool) {
	value, ok := m.secrets.Load(id)
	if !ok {
		return nil, false
	}
	secretItem := value.(struct {
		secret       []byte
		lastAccessAt time.Time
	})
	secretItem.lastAccessAt = time.Now()
	m.secrets.Store(id, secretItem)
	return secretItem.secret, true
}
