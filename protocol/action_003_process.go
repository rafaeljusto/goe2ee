package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ProcessRequestOptions contains the options for a ProcessRequest.
type ProcessRequestOptions struct {
	expectReply bool
}

// WithProcessRequestExpectReply indicates if the client is expecting a reply
// from the server. This is useful to avoid the client to wait for a reply when
// the server doesn't need to send one. By default is true.
func WithProcessRequestExpectReply(expectReply bool) func(*ProcessRequestOptions) {
	return func(o *ProcessRequestOptions) {
		o.expectReply = expectReply
	}
}

// ProcessRequest is the request sent by the client to the server with a generic
// encrypted message.
type ProcessRequest struct {
	RequestCommon

	expectReply   bool
	reservedFlags uint8
	id            [16]byte // follows RFC 4122
	messageSize   uint64
	message       []byte
}

// NewProcessRequest creates a new ProcessRequest.
func NewProcessRequest(
	id [16]byte,
	message []byte,
	optFuncs ...func(*ProcessRequestOptions),
) ProcessRequest {
	options := ProcessRequestOptions{
		expectReply: true,
	}
	for _, optFunc := range optFuncs {
		optFunc(&options)
	}
	return ProcessRequest{
		RequestCommon: RequestCommon{
			version: Version1,
			action:  ActionProcess,
		},
		expectReply: options.expectReply,
		id:          id,
		messageSize: uint64(len(message)),
		message:     message,
	}
}

// ParseProcessRequest parses a ProcessRequest received from a client. The
// request common part must have already been read. This could return an io.EOF
// error if the response is not complete.
func ParseProcessRequest(requestCommon RequestCommon, r io.Reader) (ProcessRequest, error) {
	request := ProcessRequest{
		RequestCommon: requestCommon,
	}

	var rawFlags bytes.Buffer
	n, err := io.Copy(&rawFlags, io.LimitReader(r, 1))
	switch {
	case err != nil && err != io.EOF:
		return request, fmt.Errorf("failed to read flags: %w", err)
	case n == 0:
		return request, io.ErrUnexpectedEOF
	case n != 1:
		return request, fmt.Errorf("failed to read flag: expected 1 byte but read %d bytes", n)
	}

	request.expectReply = rawFlags.Bytes()[0]&0xF0>>7 == 1
	request.reservedFlags = rawFlags.Bytes()[0] << 1 >> 1 & 0xFF

	if err := binary.Read(r, binary.LittleEndian, &request.id); err != nil {
		if err == io.ErrUnexpectedEOF {
			return request, err
		}
		return request, fmt.Errorf("failed to read id: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &request.messageSize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return request, err
		}
		return request, fmt.Errorf("failed to read size: %w", err)
	}

	request.message = make([]byte, request.messageSize)
	if err := binary.Read(r, binary.LittleEndian, &request.message); err != nil {
		if err == io.ErrUnexpectedEOF {
			return request, err
		}
		return request, fmt.Errorf("failed to read message: %w", err)
	}

	return request, nil
}

// Bytes returns the byte representation of the ProcessRequest.
func (g ProcessRequest) Bytes() []byte {
	flags := g.reservedFlags << 1 >> 1
	if g.expectReply {
		flags |= 1 << 7
	}
	buffer := g.RequestCommon.Bytes()
	buffer = append(buffer, flags)
	buffer = append(buffer, g.id[:]...)
	buffer = binary.BigEndian.AppendUint64(buffer, g.messageSize)
	buffer = append(buffer, g.message...)
	return buffer
}

// ExpectReply returns true if the client is expecting a reply from the server.
func (g ProcessRequest) ExpectReply() bool {
	return g.expectReply
}

// ID returns the id of the shared secret.
func (g ProcessRequest) ID() [16]byte {
	return g.id
}

// Message returns the encrypted message.
func (g ProcessRequest) Message() []byte {
	return g.message
}

// ProcessResponse is the response sent by the server to the client after
// generating a shared message.
type ProcessResponse struct {
	ResponseCommon

	messageSize uint64
	message     []byte
}

// NewProcessResponse creates a new NewProcessResponse.
func NewProcessResponse(message []byte) ProcessResponse {
	return ProcessResponse{
		ResponseCommon: ResponseCommon{
			success: true,
		},
		messageSize: uint64(len(message)),
		message:     message,
	}
}

// ParseProcessResponse parses a ProcessRespons received from a server. This
// could return an io.EOF error if the response is not complete.
func ParseProcessResponse(r io.Reader, responseCommon ResponseCommon) (ProcessResponse, error) {
	response := ProcessResponse{
		ResponseCommon: responseCommon,
	}

	if err := binary.Read(r, binary.BigEndian, &response.messageSize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read size: %w", err)
	}

	response.message = make([]byte, response.messageSize)
	if err := binary.Read(r, binary.LittleEndian, &response.message); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read message: %w", err)
	}

	return response, nil
}

// Bytes returns the byte representation of the ProcessResponse.
func (g ProcessResponse) Bytes() []byte {
	buffer := g.ResponseCommon.Bytes()
	buffer = binary.BigEndian.AppendUint64(buffer, g.messageSize)
	buffer = append(buffer, g.message...)
	return buffer
}

// Message returns the encrypted message.
func (g ProcessResponse) Message() []byte {
	return g.message
}
