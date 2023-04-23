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
	if err := secretManager.Store("hello", []byte("world")); err != nil {
		t.Fatalf("unexpected error storing secret: %v", err)
	}
	value, ok := secretManager.Load("hello")
	if !ok {
		t.Fatal("secret not found")
	}
	if string(value) != "world" {
		t.Fatalf("unexpected secret value %s, want %s", string(value), "world")
	}
	// max amount of time for the value to expire + GC ticker time + some extra
	// time to process the GC
	time.Sleep(200 * time.Millisecond)
	_, ok = secretManager.Load("hello")
	if ok {
		t.Fatal("secret not expired")
	}
}
