package protocol

import (
	"crypto"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
)

// HashType is the hash type used for verifying the signature.
type HashType uint8

// Supported hash types.
const (
	HashTypeSHA1   HashType = 0x1
	HashTypeSHA256 HashType = 0x2
	HashTypeSHA384 HashType = 0x3
	HashTypeSHA512 HashType = 0x4
)

// NewHashType creates a new HashType from the crypto.Hash.
func NewHashType(h crypto.Hash) HashType {
	switch h {
	case crypto.SHA1:
		return HashTypeSHA1
	case crypto.SHA256:
		return HashTypeSHA256
	case crypto.SHA384:
		return HashTypeSHA384
	case crypto.SHA512:
		return HashTypeSHA512
	default:
		panic("unsupported hash type")
	}
}

// String returns the string representation of the hash type.
func (h HashType) String() string {
	switch h {
	case HashTypeSHA1:
		return "SHA1"
	case HashTypeSHA256:
		return "SHA256"
	case HashTypeSHA384:
		return "SHA384"
	case HashTypeSHA512:
		return "SHA512"
	}
	return ""
}

// CryptoHash returns the crypto.Hash corresponding to the hash type.
func (h HashType) CryptoHash() crypto.Hash {
	switch h {
	case HashTypeSHA1:
		return crypto.SHA1
	case HashTypeSHA256:
		return crypto.SHA256
	case HashTypeSHA384:
		return crypto.SHA384
	case HashTypeSHA512:
		return crypto.SHA512
	}
	panic("unsupported hash type")
}

// SetupRequest is the request sent by the client to the server to register a
// shared secret.
type SetupRequest struct {
	RequestCommon

	id        [16]byte // follows RFC 4122
	publicKey *ecdh.PublicKey
}

// NewSetupRequest creates a new SetupRequest.
func NewSetupRequest(id [16]byte, publicKey *ecdh.PublicKey) SetupRequest {
	return SetupRequest{
		RequestCommon: RequestCommon{
			version: Version1,
			action:  ActionSetup,
		},
		id:        id,
		publicKey: publicKey,
	}
}

// ParseSetupRequest parses a SetupRequest received from a client. The request
// common part must have already been read.
func ParseSetupRequest(requestCommon RequestCommon, r io.Reader) (SetupRequest, error) {
	request := SetupRequest{
		RequestCommon: requestCommon,
	}

	if err := binary.Read(r, binary.LittleEndian, &request.id); err != nil {
		if err == io.ErrUnexpectedEOF {
			return request, err
		}
		return request, fmt.Errorf("failed to read id: %w", err)
	}

	var publicKeySize uint32
	if err := binary.Read(r, binary.BigEndian, &publicKeySize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return request, err
		}
		return request, fmt.Errorf("failed to read public key size: %w", err)
	}

	publicKeyBytes := make([]byte, publicKeySize)
	if err := binary.Read(r, binary.LittleEndian, &publicKeyBytes); err != nil {
		if err == io.ErrUnexpectedEOF {
			return request, err
		}
		return request, fmt.Errorf("failed to read public key: %w", err)
	}

	rawPublicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return request, fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey, ok := rawPublicKey.(*ecdh.PublicKey)
	if !ok {
		return request, fmt.Errorf("failed to parse public key: expected *ecdh.PublicKey but got %T", rawPublicKey)
	}
	request.publicKey = publicKey

	return request, nil
}

// Bytes returns the byte representation of the SetupRequest.
func (s SetupRequest) Bytes() []byte {
	publicKey, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		panic(fmt.Errorf("failed to encode public key: %w", err))
	}

	buffer := s.RequestCommon.Bytes()
	buffer = append(buffer, s.id[:]...)
	buffer = binary.BigEndian.AppendUint32(buffer, uint32(len(publicKey)))
	buffer = append(buffer, publicKey...)
	return buffer
}

// ID returns the id of the shared secret.
func (s SetupRequest) ID() [16]byte {
	return s.id
}

// PublicKey returns the public key for the Diffie-Hellman exchange.
func (s SetupRequest) PublicKey() *ecdh.PublicKey {
	return s.publicKey
}

// SetupResponse is the response sent by the server to the client after
// generating a shared secret.
type SetupResponse struct {
	ResponseCommon

	publicKey *ecdh.PublicKey
	hashType  HashType
	signature []byte
}

// NewSetupResponse creates a new SetupResponse.
func NewSetupResponse(publicKey *ecdh.PublicKey) SetupResponse {
	return SetupResponse{
		ResponseCommon: ResponseCommon{
			success: true,
		},
		publicKey: publicKey,
	}
}

// ParseSetupResponse parses a SetupResponse received from the server. The
// response common part must have already been read.
func ParseSetupResponse(responseCommon ResponseCommon, r io.Reader) (SetupResponse, error) {
	response := SetupResponse{
		ResponseCommon: responseCommon,
	}

	var publicKeySize uint32
	if err := binary.Read(r, binary.BigEndian, &publicKeySize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read public key size: %w", err)
	}

	publicKeyBytes := make([]byte, publicKeySize)
	if err := binary.Read(r, binary.LittleEndian, &publicKeyBytes); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read public key: %w", err)
	}

	rawPublicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return response, fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey, ok := rawPublicKey.(*ecdh.PublicKey)
	if !ok {
		return response, fmt.Errorf("failed to parse public key: expected *ecdh.PublicKey but got %T", rawPublicKey)
	}
	response.publicKey = publicKey

	if err := binary.Read(r, binary.LittleEndian, &response.hashType); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read hash type: %w", err)
	}

	var signatureSize uint32
	if err := binary.Read(r, binary.BigEndian, &signatureSize); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read signature size: %w", err)
	}

	response.signature = make([]byte, signatureSize)
	if err := binary.Read(r, binary.LittleEndian, &response.signature); err != nil {
		if err == io.ErrUnexpectedEOF {
			return response, err
		}
		return response, fmt.Errorf("failed to read signature: %w", err)
	}

	return response, nil
}

// Bytes returns the byte representation of the SetupResponse.
func (s SetupResponse) Bytes() []byte {
	publicKey, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		panic(fmt.Errorf("failed to encode public key: %w", err))
	}

	buffer := s.ResponseCommon.Bytes()
	buffer = binary.BigEndian.AppendUint32(buffer, uint32(len(publicKey)))
	buffer = append(buffer, publicKey...)
	if len(s.signature) > 0 {
		buffer = append(buffer, byte(s.hashType))
		buffer = binary.BigEndian.AppendUint32(buffer, uint32(len(s.signature)))
		buffer = append(buffer, s.signature...)
	}
	return buffer
}

// PublicKey returns the public key for the Diffie-Hellman exchange.
func (s SetupResponse) PublicKey() *ecdh.PublicKey {
	return s.publicKey
}

// HashType returns the hash type used to sign the response.
func (s SetupResponse) HashType() HashType {
	return s.hashType
}

// SetSignature sets the signature of the response.
func (s *SetupResponse) SetSignature(hashType HashType, signature []byte) {
	s.hashType = hashType
	s.signature = signature
}

// Signature prooves that the message was sent by the expected server, allowing
// to validate the response using the server's public key.
func (s SetupResponse) Signature() []byte {
	return s.signature
}
