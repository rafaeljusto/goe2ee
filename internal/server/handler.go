package server

import (
	"errors"
	"io"
	"log"
	"net"
	"os"

	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
	"github.com/rafaeljusto/goe2ee/secret"
)

// Handler is the interface that wraps the Handle method.
type Handler interface {
	Handle(w io.Writer, r io.Reader, remoteAddr net.Addr) error
}

// HandlerV1 handles requests related to the protocol version 1.
type HandlerV1 struct {
	handler    Handler
	keyManager key.ServerManager
	secrets    secret.Manager
	logger     *log.Logger
}

// NewHandlerV1 returns a new protocol version 1 handler.
func NewHandlerV1(
	handler Handler,
	keyManager key.ServerManager,
	secrets secret.Manager,
	logger *log.Logger,
) HandlerV1 {
	return HandlerV1{
		handler:    handler,
		keyManager: keyManager,
		secrets:    secrets,
		logger:     logger,
	}
}

// Handle handles the request.
func (h HandlerV1) Handle(requestCommon protocol.RequestCommon, conn net.Conn) error {
	switch requestCommon.Action() {
	case protocol.ActionHello:
		if !h.writeResponse(conn, requestCommon.Action(), protocol.NewHelloResponse().Bytes()) {
			return io.ErrShortWrite
		}
	case protocol.ActionSetup:
		return h.setupHandler(requestCommon, conn)
	case protocol.ActionProcess:
		return h.processHandler(requestCommon, conn)
	case protocol.ActionFetchKey:
		return h.fetchKeyHandler(requestCommon, conn)
	}

	return nil
}

func (h HandlerV1) writeResponse(conn io.Writer, action protocol.Action, response []byte) bool {
	n, err := conn.Write(response)
	if err == nil && n != len(response) {
		h.logger.Printf("failed to send %s action response: partial response sent, expected %d and sent %d",
			action, len(response), n)
		return false
	}
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return false
		}
		h.logger.Printf("failed to send %s action response: %v", action, err)

		if n > 0 {
			// partial number of bytes sent back to the client, can't proceed from
			// here, just close the connection
			return false
		}
		if n == 0 {
			// no bytes sent back to the client, try sending and error response
			errResponse := protocol.NewErrorResponse(
				protocol.ErrorCodeServerError,
				"failed to send back action response",
			).Bytes()

			return h.writeErrorResponse(conn, errResponse)
		}
	}
	return true
}

func (h HandlerV1) writeErrorResponse(conn io.Writer, errResponse []byte) bool {
	n, err := conn.Write(errResponse)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			h.logger.Printf("failed to send error response: %v", err)
		}
		return false
	}
	if n != len(errResponse) {
		h.logger.Printf("failed to send full error response, expected %d and sent %d", len(errResponse), n)
		return false
	}
	return true
}
