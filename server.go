package goe2ee

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	internalnet "github.com/rafaeljusto/goe2ee/internal/net"
	internalserver "github.com/rafaeljusto/goe2ee/internal/server"
	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
	"github.com/rafaeljusto/goe2ee/secret"
)

// ServerHandler is the interface that wraps the Handle method.
type ServerHandler interface {
	Handle(w io.Writer, r io.Reader, remoteAddr net.Addr) error
}

// ServerHandlerFunc is an adapter to allow the use of ordinary functions as a
// server handler.
type ServerHandlerFunc func(w io.Writer, r io.Reader, remoteAddr net.Addr) error

// Handle handles the request.
func (s ServerHandlerFunc) Handle(w io.Writer, r io.Reader, remoteAddr net.Addr) error {
	return s(w, r, remoteAddr)
}

// ServerOptions contains options for the server. You cannot modify the
// properties directly, instead use auxiliary functions when connecting to the
// server.
type ServerOptions struct {
	logger        *log.Logger
	keyManager    key.ServerManager
	secretManager secret.Manager
	readTimeout   time.Duration
	writeTimeout  time.Duration
}

// ServerWithLogger sets the logger used when handling errors. By default it
// will use the standard logger with "goe2eee" prefix.
func ServerWithLogger(logger *log.Logger) func(*ServerOptions) {
	return func(options *ServerOptions) {
		options.logger = logger
	}
}

// ServerWithKeyManager sets the key manager for the server. By default it will
// use on-the-fly key generation that is not recommended for production
// environment.
func ServerWithKeyManager(keyManager key.ServerManager) func(*ServerOptions) {
	if keyManager == nil {
		panic("key manager cannot be nil")
	}
	return func(options *ServerOptions) {
		options.keyManager = keyManager
	}
}

// ServerWithSecretManager sets the secret manager for the server. By default it
// will use an in-memory manager.
func ServerWithSecretManager(secretManager secret.Manager) func(*ServerOptions) {
	if secretManager == nil {
		panic("secret manager cannot be nil")
	}
	return func(options *ServerOptions) {
		options.secretManager = secretManager
	}
}

// ServerWithReadTimeout sets the read timeout for the server. By default it is
// 60 seconds.
func ServerWithReadTimeout(timeout time.Duration) func(*ServerOptions) {
	return func(options *ServerOptions) {
		options.readTimeout = timeout
	}
}

// ServerWithWriteTimeout sets the write timeout for the server. By default it
// is 5 seconds.
func ServerWithWriteTimeout(timeout time.Duration) func(*ServerOptions) {
	return func(options *ServerOptions) {
		options.writeTimeout = timeout
	}
}

// Server is the server-side of the E2EE protocol.
type Server struct {
	handler       ServerHandler
	logger        *log.Logger
	keyManager    key.ServerManager
	secretManager secret.Manager
	readTimeout   time.Duration
	writeTimeout  time.Duration
	quit          chan struct{}
	wg            sync.WaitGroup
}

// NewServer returns a new server. The handler is called whenever a new message
// arrives, so it should handle a single round-trip.
func NewServer(handler ServerHandler, optFuncs ...func(*ServerOptions)) *Server {
	options := ServerOptions{
		logger:        log.New(os.Stderr, "[goe2ee] ", log.LstdFlags),
		secretManager: secret.NewInMemoryManager(),
		readTimeout:   60 * time.Second,
		writeTimeout:  5 * time.Second,
	}
	for _, f := range optFuncs {
		f(&options)
	}
	// If no key manager is provided, we generate one on the fly. Chances of the
	// key generation failing are very low and could occur if there's some issue
	// reading the random source, in this case the library will panic. It's not
	// recommended to use on-the-fly key generation in production.
	if options.keyManager == nil {
		var err error
		options.keyManager, err = key.ServerManagerGenerateOnTheFly(protocol.KeyAlgorithmED25519)
		if err != nil {
			panic(fmt.Sprintf("failed to create key manager: %v", err))
		}
	}
	return &Server{
		handler:       handler,
		logger:        options.logger,
		keyManager:    options.keyManager,
		secretManager: options.secretManager,
		readTimeout:   options.readTimeout,
		writeTimeout:  options.writeTimeout,
		quit:          make(chan struct{}),
	}
}

// StartTCP starts the server listening on the given hostport. This is
// non-blocking and returns the listening local address.
func (s *Server) StartTCP(hostport string) (net.Addr, error) {
	listen, err := net.Listen("tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on '%s': %w", hostport, err)
	}
	teardown := func() {
		if err := listen.Close(); err != nil {
			s.logger.Printf("failed to close listener: %v", err)
		}
	}

	go func(listen net.Listener, logger *log.Logger) {
		defer teardown()

		for {
			select {
			case <-s.quit:
				return
			default:
			}

			conn, err := listen.Accept()
			if err != nil {
				logger.Printf("failed to accept connection: %v", err)
				continue
			}

			s.wg.Add(1)
			go s.handleConnection(conn, logger)
		}
	}(listen, s.logger)

	return listen.Addr(), nil
}

func (s *Server) handleConnection(conn net.Conn, logger *log.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Print(r)
		}
		if err := conn.Close(); err != nil {
			logger.Printf("failed to close connection: %v", err)
		}
		s.wg.Done()
	}()

	handler := internalserver.NewHandlerV1(s.handler, s.keyManager, s.secretManager, s.logger)

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		referenceTime := time.Now()
		if s.readTimeout > 0 {
			if err := conn.SetReadDeadline(referenceTime.Add(s.readTimeout)); err != nil {
				logger.Printf("failed to set connection read deadline: %v", err)
			}
		}
		if s.writeTimeout > 0 {
			if err := conn.SetWriteDeadline(referenceTime.Add(s.writeTimeout)); err != nil {
				logger.Printf("failed to set connection write deadline: %v", err)
			}
		}

		requestCommon, err := protocol.ParseRequestCommon(conn)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				logger.Printf("connection closed by client (%s)", conn.RemoteAddr())
			} else {
				logger.Printf("failed to parse request common: %v", err)
			}
			// we don't need to send an error response because we don't know the
			// version yet, so just close the connection.
			break
		}

		if requestCommon.Version() != protocol.Version1 {
			logger.Printf("unsupported version: %d", requestCommon.Version())
			// we don't need to send an error response because we don't support the
			// version, so just close the connection.
			break
		}

		if err := handler.Handle(requestCommon, conn); err != nil {
			if err == io.EOF || err == io.ErrShortWrite || err == io.ErrUnexpectedEOF {
				logger.Printf("connection closed by client (%s)", conn.RemoteAddr())
			} else {
				logger.Printf("failed to handle request: %v", err)
			}
			break
		}
	}
}

// StartUDP starts the server listening on the given hostport. This is
// non-blocking and returns the listening local address.
func (s *Server) StartUDP(hostport string) (net.Addr, error) {
	conn, err := net.ListenPacket("udp", hostport)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on '%s': %w", hostport, err)
	}
	teardown := func() {
		if err := conn.Close(); err != nil {
			s.logger.Printf("failed to close connection: %v", err)
		}
	}

	go func(logger *log.Logger) {
		defer teardown()
		s.handlePacketConnection(conn, logger)
	}(s.logger)

	return conn.LocalAddr(), nil
}

func (s *Server) handlePacketConnection(conn net.PacketConn, logger *log.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Print(r)
		}
	}()

	handler := internalserver.NewHandlerV1(s.handler, s.keyManager, s.secretManager, s.logger)

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		if s.readTimeout > 0 {
			referenceTime := time.Now()
			if err := conn.SetReadDeadline(referenceTime.Add(s.readTimeout)); err != nil {
				logger.Printf("failed to set connection read deadline: %v", err)
			}
		}

		udpConn := internalnet.NewUDPConn(conn)
		if _, err := udpConn.Receive(); err != nil {
			logger.Printf("failed to read from connection: %v", err)
			continue
		}

		go func(udpConn *internalnet.UDPConn) {
			defer func() {
				if r := recover(); r != nil {
					logger.Print(r)
				}
			}()

			defer func() {
				if err := udpConn.Close(); err != nil {
					logger.Printf("failed to close connection: %v", err)
				}
			}()

			if s.writeTimeout > 0 {
				referenceTime := time.Now()
				if err := conn.SetWriteDeadline(referenceTime.Add(s.writeTimeout)); err != nil {
					logger.Printf("failed to set connection write deadline: %v", err)
				}
			}

			requestCommon, err := protocol.ParseRequestCommon(udpConn)
			if err != nil {
				if err == io.EOF {
					logger.Printf("connection closed by client (%s)", conn.LocalAddr())
				} else {
					logger.Printf("failed to parse request common: %v", err)
				}
				// we don't need to send an error response because we don't know the
				// version yet, so just close the connection.
				return
			}

			if requestCommon.Version() != protocol.Version1 {
				logger.Printf("unsupported version: %d", requestCommon.Version())
				// we don't need to send an error response because we don't support the
				// version, so just close the connection.
				return
			}

			if err := handler.Handle(requestCommon, udpConn); err != nil {
				if err == io.EOF || err == io.ErrShortWrite || err == io.ErrUnexpectedEOF {
					logger.Printf("connection closed by client (%s)", conn.LocalAddr())
				} else {
					logger.Printf("failed to handle request: %v", err)
				}
				return
			}
		}(udpConn)
	}
}

// Close closes the server. It will wait for all client connections to finish.
func (s *Server) Close() error {
	close(s.quit)
	s.wg.Wait()
	return nil
}
