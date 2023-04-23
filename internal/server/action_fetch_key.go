package server

import (
	"crypto/x509"
	"io"

	"github.com/rafaeljusto/goe2ee/protocol"
)

func (h HandlerV1) fetchKeyHandler(requestCommon protocol.RequestCommon, conn io.ReadWriter) error {
	keyAlgorithm, publicKey, err := h.keyManager.FetchKey()
	if err != nil {
		h.logger.Printf("failed to fetch public key: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to fetch public key",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}
	publicKeyRaw, err := x509.MarshalPKIXPublicKey(publicKey.PublicKey)
	if err != nil {
		h.logger.Printf("failed to encode public key: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to encode public key",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}
	if !h.writeResponse(
		conn,
		requestCommon.Action(),
		protocol.NewFetchKeyResponse(keyAlgorithm, publicKeyRaw).Bytes(),
	) {
		return io.ErrShortWrite
	}
	return nil
}
