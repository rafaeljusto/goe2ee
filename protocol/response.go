package protocol

import (
	"bytes"
	"fmt"
	"io"
)

// ResponseCommon is the common fields for all responses.
type ResponseCommon struct {
	success       bool
	reservedFlags uint8
}

// ParseResponseCommon parses the common fields of a response.  It could return
// io.EOF if the server closes the connection.
func ParseResponseCommon(r io.Reader) (ResponseCommon, error) {
	var response ResponseCommon

	var flags bytes.Buffer
	n, err := io.Copy(&flags, io.LimitReader(r, 1))
	switch {
	case err != nil && err != io.EOF:
		return response, fmt.Errorf("failed to read flags: %w", err)
	case n == 0:
		return response, io.ErrUnexpectedEOF
	case n != 1:
		return response, fmt.Errorf("failed to read flags: expected 1 byte but read %d bytes", n)
	}
	response.success = flags.Bytes()[0]>>7 == 1
	response.reservedFlags = flags.Bytes()[0] << 1 >> 1

	return response, nil
}

// Bytes returns the byte representation of the response.
func (r ResponseCommon) Bytes() []byte {
	var buffer []byte
	if r.success {
		buffer = append(buffer, uint8(1)<<7|r.reservedFlags)
	} else {
		buffer = append(buffer, 0|r.reservedFlags)
	}
	return buffer
}

// Success returns true if the action was successful.
func (r ResponseCommon) Success() bool {
	return r.success
}
