package server

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"

	"github.com/rafaeljusto/goe2ee/protocol"
)

func (h HandlerV1) setupHandler(requestCommon protocol.RequestCommon, conn net.Conn) error {
	request, err := protocol.ParseSetupRequest(requestCommon, conn)
	if err != nil {
		h.logger.Printf("failed to parse setup action request: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeMalformedRequest,
			"failed to parse data of the request",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	serverPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		h.logger.Printf("failed to generate private key: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeMalformedRequest,
			"failed to generate private key",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	secret, err := serverPrivateKey.ECDH(request.PublicKey())
	if err != nil {
		h.logger.Printf("failed to generate shared secret: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeMalformedRequest,
			"failed to generate shared secret",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	id := request.ID()
	idHash := sha256.New()

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		h.logger.Printf("failed to split host and port: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to split host and port",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	if n, err := idHash.Write([]byte(host)); err != nil {
		h.logger.Printf("failed to write host to hash: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to write host to hash",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	} else if n != len(host) {
		h.logger.Printf("failed to write host to hash: expected writing %d bytes but wrote %d bytes", len(host), n)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to write host to hash",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}
	if n, err := idHash.Write(id[:]); err != nil {
		h.logger.Printf("failed to write ID to hash: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to write ID to hash",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	} else if n != len(id) {
		h.logger.Printf("failed to write ID to hash: expected writing %d bytes but wrote %d bytes", len(id), n)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to write ID to hash",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	err = h.secrets.Store(base64.StdEncoding.EncodeToString(idHash.Sum(nil)), secret)
	if err != nil {
		h.logger.Printf("failed to store shared secret: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to store shared secret",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	response := protocol.NewSetupResponse(serverPrivateKey.PublicKey())

	hashType := crypto.SHA512
	signature, err := h.keyManager.Sign(hashType, response.Bytes())
	if err != nil {
		h.logger.Printf("failed to sign response: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to sign response",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}
	response.SetSignature(protocol.NewHashType(hashType), signature)

	if !h.writeResponse(conn, requestCommon.Action(), response.Bytes()) {
		return io.ErrShortWrite
	}
	return nil
}
