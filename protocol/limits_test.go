package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestParseProcessRequestRejectsOversizedMessage ensures a peer cannot make the
// parser allocate an arbitrary amount of memory by advertising a huge message
// size. Without the cap this would attempt make([]byte, MaxMessageSize+1).
func TestParseProcessRequestRejectsOversizedMessage(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0)            // flags
	buf.Write(make([]byte, 16)) // id
	buf.Write(make([]byte, 8))  // counter
	var size [8]byte            // messageSize (BigEndian uint64)
	binary.BigEndian.PutUint64(size[:], uint64(MaxMessageSize)+1)
	buf.Write(size[:])

	_, err := ParseProcessRequest(RequestCommon{}, &buf)
	if err == nil {
		t.Fatal("expected an error for oversized message size")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected a size-limit error but got: %v", err)
	}
}

// TestParseSetupRequestRejectsOversizedKey ensures the public key size field is
// bounded.
func TestParseSetupRequestRejectsOversizedKey(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(make([]byte, 16)) // id
	var size [4]byte            // publicKeySize (BigEndian uint32)
	binary.BigEndian.PutUint32(size[:], uint32(MaxKeySize)+1)
	buf.Write(size[:])

	_, err := ParseSetupRequest(RequestCommon{}, &buf)
	if err == nil {
		t.Fatal("expected an error for oversized public key size")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected a size-limit error but got: %v", err)
	}
}
