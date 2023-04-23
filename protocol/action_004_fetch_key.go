package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// KeyAlgorithm is the algorithm used to generate the key-pair.
type KeyAlgorithm uint8

// Supported key algorithms.
const (
	KeyAlgorithmRSA     KeyAlgorithm = 0x1
	KeyAlgorithmECDSA   KeyAlgorithm = 0x2
	KeyAlgorithmED25519 KeyAlgorithm = 0x3
)

// String returns the string representation of the key algorithm.
func (k KeyAlgorithm) String() string {
	if k == KeyAlgorithmRSA {
		return "RSA"
	}
	return ""
}

// FetchKeyRequest is the request sent by the client to the server to retrieve
// the public key.
type FetchKeyRequest struct {
	RequestCommon
}

// NewFetchKeyRequest creates a new FetchKeyRequest.
func NewFetchKeyRequest() FetchKeyRequest {
	return FetchKeyRequest{
		RequestCommon: RequestCommon{
			version: Version1,
			action:  ActionFetchKey,
		},
	}
}

// FetchKeyResponse is the response sent by the server to the client containing
// the public key.
type FetchKeyResponse struct {
	ResponseCommon

	keyAlgorithm  KeyAlgorithm
	publicKeySize uint64
	publicKey     []byte
}

// NewFetchKeyResponse creates a new NewFetchKeyResponse.
func NewFetchKeyResponse(keyAlgorithm KeyAlgorithm, publicKey []byte) FetchKeyResponse {
	return FetchKeyResponse{
		ResponseCommon: ResponseCommon{
			success: true,
		},
		keyAlgorithm:  keyAlgorithm,
		publicKeySize: uint64(len(publicKey)),
		publicKey:     publicKey,
	}
}

// ParseFetchKeyResponse parses a FetchKeyRespons received from a server.
func ParseFetchKeyResponse(r io.Reader, responseCommon ResponseCommon) (FetchKeyResponse, error) {
	response := FetchKeyResponse{
		ResponseCommon: responseCommon,
	}

	if err := binary.Read(r, binary.BigEndian, &response.keyAlgorithm); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read algorithm: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &response.publicKeySize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read size: %w", err)
	}

	response.publicKey = make([]byte, response.publicKeySize)
	if err := binary.Read(r, binary.LittleEndian, &response.publicKey); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read public key: %w", err)
	}

	return response, nil
}

// Bytes returns the byte representation of the FetchKeyResponse.
func (g FetchKeyResponse) Bytes() []byte {
	buffer := g.ResponseCommon.Bytes()
	buffer = append(buffer, byte(g.keyAlgorithm))
	buffer = binary.BigEndian.AppendUint64(buffer, g.publicKeySize)
	buffer = append(buffer, g.publicKey...)
	return buffer
}

// KeyAlgorithm returns the algorithm used to generate the key-pair.
func (g FetchKeyResponse) KeyAlgorithm() KeyAlgorithm {
	return g.keyAlgorithm
}

// PublicKey returns the public key.
func (g FetchKeyResponse) PublicKey() []byte {
	return g.publicKey
}
