package protocol

import "encoding/binary"

// Direction bytes distinguish the two halves of a conversation so that the
// client and the server never derive the same AEAD nonce from the same counter
// under the shared secret.
const (
	DirectionClientToServer byte = 0x00
	DirectionServerToClient byte = 0x01
)

// Nonce builds a deterministic AEAD nonce of the given size from a direction
// byte and a message counter. Using a direction byte plus a per-secret
// monotonic counter guarantees the nonce is never reused under the same key,
// which is required for the security of AES-GCM. The size must be at least 9
// bytes (one direction byte plus an 8-byte counter); GCM uses 12.
func Nonce(direction byte, counter uint64, size int) []byte {
	nonce := make([]byte, size)
	nonce[0] = direction
	binary.BigEndian.PutUint64(nonce[size-8:], counter)
	return nonce
}
