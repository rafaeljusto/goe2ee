package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"

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

	secret, ok := h.secrets.Load(base64.StdEncoding.EncodeToString(idHash.Sum(nil)))
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

	aes, err := aes.NewCipher(secret)
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

	nonceSize := gcm.NonceSize()
	encryptedMessage := request.Message()
	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]
	message, err := gcm.Open(nil, nonce, ciphertext, nil)
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

	nonce = make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		h.logger.Printf("failed to generate nonce: %v", err)
		errResponse := protocol.NewErrorResponse(
			protocol.ErrorCodeServerError,
			"failed to generate nonce",
		).Bytes()
		if !h.writeErrorResponse(conn, errResponse) {
			return io.ErrShortWrite
		}
		return nil
	}

	if request.ExpectReply() {
		writerBuffer := writer.(*bytes.Buffer)
		response := protocol.NewProcessResponse(gcm.Seal(nonce, nonce, writerBuffer.Bytes(), nil)).Bytes()
		if !h.writeResponse(conn, requestCommon.Action(), response) {
			return io.ErrShortWrite
		}
	}
	return nil
}
