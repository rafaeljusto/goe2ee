// Package secret provides a simple interface to store and load sessions
// (shared secrets together with their replay-protection state). It also
// provides some built-in implementations.
package secret

import (
	"sync"
	"time"
)

// replayWindowSize is the number of counters tracked behind the highest seen
// value. Messages older than this window are rejected. A window is required
// because the client connection pool reuses a single shared secret across
// several concurrent connections, so authenticated messages can legitimately
// arrive out of order.
const replayWindowSize = 64

// ReplayWindow is a sliding-window replay filter (in the style of the IPsec
// anti-replay algorithm, RFC 6479). It is safe for concurrent use.
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	bitmap  uint64
}

// CheckAndUpdate reports whether counter is fresh: not previously seen and not
// older than the window. When it returns true the counter is recorded so that
// a later call with the same value returns false. Counters must start at 1; a
// counter of 0 is always rejected.
func (w *ReplayWindow) CheckAndUpdate(counter uint64) bool {
	if counter == 0 {
		return false
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if counter > w.highest {
		shift := counter - w.highest
		if shift >= replayWindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = counter
		return true
	}

	diff := w.highest - counter
	if diff >= replayWindowSize {
		// too old, outside the window
		return false
	}
	mask := uint64(1) << diff
	if w.bitmap&mask != 0 {
		// already seen
		return false
	}
	w.bitmap |= mask
	return true
}

// Session bundles a shared secret with the state needed to reject replayed
// messages that use it. Store implementations must preserve the Replay pointer
// so that its state persists for the lifetime of the secret.
type Session struct {
	Secret []byte
	Replay *ReplayWindow
}

// NewSession creates a Session for the given shared secret with a fresh replay
// window.
func NewSession(secret []byte) *Session {
	return &Session{
		Secret: secret,
		Replay: &ReplayWindow{},
	}
}

// Manager is the interface that wraps the basic operations to store and load a
// session.
type Manager interface {
	Store(id string, session *Session) error
	Load(id string) (*Session, bool)
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

// InMemoryManagerWithTTL sets the amount of time that the session will be
// stored after it is idle (not accessed anymore). By default, the session will
// be stored for 15 minutes.
func InMemoryManagerWithTTL(ttl time.Duration) func(*InMemoryManagerOptions) {
	return func(o *InMemoryManagerOptions) {
		o.ttl = ttl
	}
}

type inMemorySession struct {
	session      *Session
	lastAccessAt time.Time
}

// InMemoryManager is a manager that stores the sessions in memory.
type InMemoryManager struct {
	secrets sync.Map
	quit    chan struct{}
	once    sync.Once
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
	m := &InMemoryManager{
		quit: make(chan struct{}),
	}
	if options.ttl > 0 {
		go func() {
			timeTicker := time.NewTicker(options.gcTicker)
			defer timeTicker.Stop()

			for {
				select {
				case <-m.quit:
					return
				case <-timeTicker.C:
					m.secrets.Range(func(key, value interface{}) bool {
						item := value.(inMemorySession)
						if time.Since(item.lastAccessAt) > options.ttl {
							m.secrets.Delete(key)
						}
						return true
					})
				}
			}
		}()
	}
	return m
}

// Store stores the session in memory.
func (m *InMemoryManager) Store(id string, session *Session) error {
	m.secrets.Store(id, inMemorySession{
		session:      session,
		lastAccessAt: time.Now(),
	})
	return nil
}

// Load loads the session from memory.
func (m *InMemoryManager) Load(id string) (*Session, bool) {
	value, ok := m.secrets.Load(id)
	if !ok {
		return nil, false
	}
	item := value.(inMemorySession)
	item.lastAccessAt = time.Now()
	m.secrets.Store(id, item)
	return item.session, true
}

// Close stops the background garbage collector goroutine. It is safe to call
// more than once.
func (m *InMemoryManager) Close() error {
	m.once.Do(func() {
		close(m.quit)
	})
	return nil
}
