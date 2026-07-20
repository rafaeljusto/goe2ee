package secret_test

import (
	"testing"
	"time"

	"github.com/rafaeljusto/goe2ee/secret"
)

func TestInMemoryManager(t *testing.T) {
	secretManager := secret.NewInMemoryManager(
		secret.InMemoryManagerWithGCTicker(50*time.Millisecond),
		secret.InMemoryManagerWithTTL(100*time.Millisecond),
	)
	defer func() {
		if err := secretManager.Close(); err != nil {
			t.Fatalf("unexpected error closing manager: %v", err)
		}
	}()

	if err := secretManager.Store("hello", secret.NewSession([]byte("world"))); err != nil {
		t.Fatalf("unexpected error storing secret: %v", err)
	}
	session, ok := secretManager.Load("hello")
	if !ok {
		t.Fatal("secret not found")
	}
	if string(session.Secret) != "world" {
		t.Fatalf("unexpected secret value %s, want %s", string(session.Secret), "world")
	}
	// max amount of time for the value to expire + GC ticker time + some extra
	// time to process the GC
	time.Sleep(200 * time.Millisecond)
	_, ok = secretManager.Load("hello")
	if ok {
		t.Fatal("secret not expired")
	}
}

func TestReplayWindow(t *testing.T) {
	var w secret.ReplayWindow

	// A counter of 0 is never valid.
	if w.CheckAndUpdate(0) {
		t.Fatal("counter 0 should be rejected")
	}

	// First sighting of increasing counters is accepted.
	for _, c := range []uint64{1, 2, 3, 10} {
		if !w.CheckAndUpdate(c) {
			t.Fatalf("counter %d should be accepted on first sight", c)
		}
	}

	// Replays are rejected.
	for _, c := range []uint64{1, 2, 3, 10} {
		if w.CheckAndUpdate(c) {
			t.Fatalf("counter %d should be rejected as a replay", c)
		}
	}

	// Out-of-order but still within the window is accepted once.
	if !w.CheckAndUpdate(5) {
		t.Fatal("counter 5 should be accepted (within window, not seen)")
	}
	if w.CheckAndUpdate(5) {
		t.Fatal("counter 5 should be rejected on replay")
	}

	// Anything too far behind the highest is rejected.
	if !w.CheckAndUpdate(1000) {
		t.Fatal("counter 1000 should be accepted")
	}
	if w.CheckAndUpdate(1000 - 64) {
		t.Fatal("counter older than the window should be rejected")
	}
}
