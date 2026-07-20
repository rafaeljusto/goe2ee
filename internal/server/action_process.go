package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"

	"github.com/rafaeljusto/goe2ee/internal/kdf"
	"github.com/rafaeljusto/goe2ee/protocol"
)

func (h HandlerV1) processHandler(requestCommon protocol.RequestCommon, conn net.Conn) error {
	request, err := protocol.ParseProcessRequest(requestCommon, conn)
	if err != nil {
		h.logger.Printf("failed to parse process action request: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeMalformedRequest,
			"failed to parse data of the request",
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

	session, ok := h.secrets.Load(base64.StdEncoding.EncodeToString(idHash.Sum(nil)))
	if !ok {
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeUnknownClient,
			"could not find a shared secret matching the given ID",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	// Reject replayed or too-old messages before doing any cryptographic work.
	if !session.Replay.CheckAndUpdate(request.Counter()) {
		h.logger.Printf("replay detected for counter %d", request.Counter())
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeReplayDetected,
			"message counter was already seen or is too old",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	aesKey, err := kdf.DeriveKey(session.Secret, kdf.Info, kdf.AESKeySize)
	if err != nil {
		h.logger.Printf("failed to derive encryption key: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to derive encryption key",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	aes, err := aes.NewCipher(aesKey)
	if err != nil {
		h.logger.Printf("failed to create AES cipher: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to create AES cipher",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		h.logger.Printf("failed to create GCM cipher: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to create GCM cipher",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	// The nonce is derived deterministically from the message counter and the
	// direction, so it is not carried on the wire; the message is the ciphertext.
	nonce := protocol.Nonce(protocol.DirectionClientToServer, request.Counter(), gcm.NonceSize())
	message, err := gcm.Open(nil, nonce, request.Message(), nil)
	if err != nil {
		h.logger.Printf("failed to decrypt message: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to decrypt message",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	var writer io.Writer
	if request.ExpectReply() {
		writer = &bytes.Buffer{}
	} else {
		writer = io.Discard
	}
	reader := bytes.NewBuffer(message)
	if err := h.handler.Handle(writer, reader, conn.RemoteAddr()); err != nil {
		h.logger.Printf("failed to handle message: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to handle message",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	if request.ExpectReply() {
		writerBuffer := writer.(*bytes.Buffer)
		// Reuse the request counter (with the opposite direction) for the reply
		// nonce. It is unique per secret, so the derived nonce is never reused.
		responseNonce := protocol.Nonce(protocol.DirectionServerToClient, request.Counter(), gcm.NonceSize())
		response := protocol.NewProcessResponse(
			request.Counter(),
			gcm.Seal(nil, responseNonce, writerBuffer.Bytes(), nil),
		).Bytes()
		if !h.writeResponse(conn, requestCommon.Action(), response) {
			return io.ErrShortWrite
		}
	}
	return nil
}
