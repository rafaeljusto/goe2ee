package protocol

import (
	"bytes"
	"fmt"
	"io"
)

// Version is the protocol version.
type Version uint8

// List of supported versions.
const (
	Version1 Version = 1
)

// RequestCommon is the common fields for all requests.
type RequestCommon struct {
	version Version
	action  Action
}

// ParseRequestCommon parses the common fields of a request. It could return
// io.EOF if the client closes the connection.
func ParseRequestCommon(r io.Reader) (RequestCommon, error) {
	var request RequestCommon

	var rawAction bytes.Buffer
	n, err := io.Copy(&rawAction, io.LimitReader(r, 1))
	switch {
	case err != nil && err != io.EOF:
		return request, fmt.Errorf("failed to read action: %w", err)
	case n == 0:
		return request, io.ErrUnexpectedEOF
	case n != 1:
		return request, fmt.Errorf("failed to read action: expected 1 byte but read %d bytes", n)
	}

	request.version = Version(rawAction.Bytes()[0] & 0xF0 >> 4)
	request.action = Action(rawAction.Bytes()[0] & 0x0F)
	return request, nil
}

// Bytes returns the byte representation of the request.
func (r RequestCommon) Bytes() []byte {
	var buffer []byte
	buffer = append(buffer, uint8(r.version)<<4|uint8(r.action))
	return buffer
}

// Version returns the protocol version.
func (r RequestCommon) Version() Version {
	return r.version
}

// Action returns the action to be performed.
func (r RequestCommon) Action() Action {
	return r.action
}
