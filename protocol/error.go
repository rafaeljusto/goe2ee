package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ErrorCode is the error code sent by the server.
type ErrorCode uint32

// List of possible error codes.
const (
	ErrorCodeMalformedRequest   ErrorCode = 0x01
	ErrorCodeServerError        ErrorCode = 0x02
	ErrorCodeUnknownClient      ErrorCode = 0x03
	ErrorCodeUnsupportedVersion ErrorCode = 0x04
)

// ErrorResponse is the response sent by the server to the client when an error
// occurs.
type ErrorResponse struct {
	ResponseCommon

	errorCode    ErrorCode
	errorMessage string
}

// NewErrorResponse creates a new ErrorResponse.
func NewErrorResponse(errorCode ErrorCode, errorMessage string) ErrorResponse {
	return ErrorResponse{
		ResponseCommon: ResponseCommon{
			success: false,
		},
		errorCode:    errorCode,
		errorMessage: errorMessage,
	}
}

// ParseErrorResponse parses an ErrorResponse received from the server.
func ParseErrorResponse(r io.Reader, responseCommon ResponseCommon) (ErrorResponse, error) {
	response := ErrorResponse{
		ResponseCommon: responseCommon,
	}

	if err := binary.Read(r, binary.BigEndian, &response.errorCode); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read error code: %w", err)
	}

	var errorMessageSize uint64
	if err := binary.Read(r, binary.BigEndian, &errorMessageSize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read size: %w", err)
	}

	if errorMessageSize > 0 {
		var errorMessage bytes.Buffer
		n, err := io.Copy(&errorMessage, io.LimitReader(r, int64(errorMessageSize)))
		if err != nil && err != io.EOF {
			return response, fmt.Errorf("failed to read error message: %w", err)
		} else if n != int64(errorMessageSize) {
			return response, fmt.Errorf("failed to read error message: expected %d bytes but read %d bytes",
				errorMessageSize, n)
		}
		response.errorMessage = errorMessage.String()
	}

	return response, nil
}

// Bytes returns the byte representation of the response.
func (e ErrorResponse) Bytes() []byte {
	buffer := e.ResponseCommon.Bytes()
	buffer = binary.BigEndian.AppendUint32(buffer, uint32(e.errorCode))
	buffer = binary.BigEndian.AppendUint64(buffer, uint64(len(e.errorMessage)))
	buffer = append(buffer, []byte(e.errorMessage)...)
	return buffer
}

// ErrorCode returns the error code if the action failed.
func (e ErrorResponse) ErrorCode() ErrorCode {
	return e.errorCode
}

// ErrorMessage returns the error message if the action failed.
func (e ErrorResponse) ErrorMessage() string {
	return e.errorMessage
}
