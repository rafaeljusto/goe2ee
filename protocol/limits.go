package protocol

// Maximum sizes accepted when parsing length-prefixed fields received from the
// network. Without these bounds a peer could advertise an arbitrarily large
// size and force the parser to allocate that much memory (or panic), which is a
// trivial denial-of-service vector. The limits are generous relative to any
// legitimate value while still preventing pathological allocations.
const (
	// MaxKeySize is the maximum size in bytes accepted for a marshalled public
	// key field.
	MaxKeySize = 1 << 16 // 64 KiB

	// MaxSignatureSize is the maximum size in bytes accepted for a signature
	// field.
	MaxSignatureSize = 1 << 16 // 64 KiB

	// MaxMessageSize is the maximum size in bytes accepted for an encrypted
	// message payload.
	MaxMessageSize = 1 << 30 // 1 GiB
)
