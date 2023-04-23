package goe2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	internalclient "github.com/rafaeljusto/goe2ee/internal/client"
	internalnet "github.com/rafaeljusto/goe2ee/internal/net"
	"github.com/rafaeljusto/goe2ee/key"
	"github.com/rafaeljusto/goe2ee/protocol"
)

// make sure the client implements the net.Conn interface.
var _ net.Conn = (*Client)(nil)

// ClientOptions contains options for the client. You cannot modify the
// properties directly, instead use auxiliary functions when connecting to the
// server.
type ClientOptions struct {
	keyFetcher   key.ClientFetcher
	readTimeout  time.Duration
	writeTimeout time.Duration
	keepAlive    bool
	expectReply  bool
}

func clientOptionsDefaults() ClientOptions {
	return ClientOptions{
		keyFetcher:   key.NewClientFetcherDNSKEY(key.GoogleDNSProvider),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
		keepAlive:    false,
		expectReply:  true,
	}
}

// ClientWithKeyFetcher sets the strategy used to retrieve the server's public
// key. By default it will use DNS over HTTPS to retrieve the DNSKEY resource
// record of the host using Google's provider.
func ClientWithKeyFetcher(keyFetcher key.ClientFetcher) func(*ClientOptions) {
	if keyFetcher == nil {
		panic("keyFetcher cannot be nil")
	}
	return func(options *ClientOptions) {
		options.keyFetcher = keyFetcher
	}
}

// ClientWithReadTimeout sets the read timeout for the client. By default it is
// 5 seconds.
func ClientWithReadTimeout(timeout time.Duration) func(*ClientOptions) {
	return func(options *ClientOptions) {
		options.readTimeout = timeout
	}
}

// ClientWithWriteTimeout sets the write timeout for the client. By default it
// is 5 seconds.
func ClientWithWriteTimeout(timeout time.Duration) func(*ClientOptions) {
	return func(options *ClientOptions) {
		options.writeTimeout = timeout
	}
}

// ClientWithKeepAlive sets the keep-alive option for the client. By default it
// is false.
func ClientWithKeepAlive(keepAlive bool) func(*ClientOptions) {
	return func(options *ClientOptions) {
		options.keepAlive = keepAlive
	}
}

// ClientWithExpectReply sets the expect-reply option for the client. By default
// it is true.
func ClientWithExpectReply(expectReply bool) func(*ClientOptions) {
	return func(options *ClientOptions) {
		options.expectReply = expectReply
	}
}

// Client is the client-side of the E2EE protocol. It implements the net.Conn
// interface to be used as a regular connection.
type Client struct {
	hostport     string
	pool         *ClientPool
	conn         net.Conn
	keyFetcher   key.ClientFetcher
	readTimeout  time.Duration
	writeTimeout time.Duration
	expectReply  bool
	secret       []byte
	id           [16]byte
	buffer       bytes.Buffer
}

// DialTCP connects to the server using TCP. The hostport follows the pattern
// "host:port", the host can be a domain name or an IP address.
func DialTCP(hostport string, optFunc ...func(*ClientOptions)) (*Client, error) {
	client, err := dialTCP(hostport, optFunc...)
	if err != nil {
		return nil, err
	}
	if err := client.handshake(); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}
	return client, nil
}

func dialTCP(hostport string, optFunc ...func(*ClientOptions)) (*Client, error) {
	options := clientOptionsDefaults()
	for _, f := range optFunc {
		f(&options)
	}

	// resolve tcp address
	tcpAddr, err := net.ResolveTCPAddr("tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tcp address '%s': %w", hostport, err)
	}

	// connect to server
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server '%s': %w", tcpAddr.String(), err)
	}

	if err := conn.SetKeepAlive(options.keepAlive); err != nil {
		return nil, fmt.Errorf("failed to set keep-alive option: %w", err)
	}

	return &Client{
		hostport:     hostport,
		conn:         conn,
		keyFetcher:   options.keyFetcher,
		readTimeout:  options.readTimeout,
		writeTimeout: options.writeTimeout,
		expectReply:  options.expectReply,
	}, nil
}

// DialUDP connects to the server using UDP. The hostport follows the pattern
// "host:port", the host can be a domain name or an IP address.
func DialUDP(hostport string, optFunc ...func(*ClientOptions)) (*Client, error) {
	client, err := dialUDP(hostport, optFunc...)
	if err != nil {
		return nil, err
	}
	if err := client.handshake(); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}
	return client, nil
}

func dialUDP(hostport string, optFunc ...func(*ClientOptions)) (*Client, error) {
	options := clientOptionsDefaults()
	for _, f := range optFunc {
		f(&options)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve udp address '%s': %w", hostport, err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server '%s': %w", udpAddr.String(), err)
	}

	return &Client{
		hostport: hostport,
		conn: internalnet.NewUDPConn(conn,
			internalnet.WithUDPConnBufferedWrite(false),
		),
		keyFetcher:   options.keyFetcher,
		readTimeout:  options.readTimeout,
		writeTimeout: options.writeTimeout,
		expectReply:  options.expectReply,
	}, nil
}

func (c *Client) handshake() error {
	host, _, err := net.SplitHostPort(c.hostport)
	if err != nil {
		return fmt.Errorf("failed to split host and port from '%s': %w", c.hostport, err)
	}

	// retrieve server's public key
	serverPublicKey, err := c.keyFetcher.Fetch(host)
	if err != nil {
		return err
	}

	// generate ID (RFC 4122)
	id, err := internalclient.UUID()
	if err != nil {
		return err
	}

	clientPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// send the public Elliptic Curve Diffie-Hellman key
	setupRequest := protocol.NewSetupRequest(id, clientPrivateKey.PublicKey())
	n, err := c.conn.Write(setupRequest.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send setup request to '%s': %w", c.hostport, err)
	} else if n != len(setupRequest.Bytes()) {
		return fmt.Errorf("failed to send setup request to '%s': "+
			"expected sending %d bytes but sent %d bytes", c.hostport, len(setupRequest.Bytes()), n)
	}

	// check if the server accepted the secret
	responseCommon, err := protocol.ParseResponseCommon(c.conn)
	if err != nil {
		return fmt.Errorf("failed to parse response from '%s': %w", c.hostport, err)
	}

	if !responseCommon.Success() {
		errorResponse, err := protocol.ParseErrorResponse(c.conn, responseCommon)
		if err != nil {
			return fmt.Errorf("failed to parse error response from '%s': %w", c.hostport, err)
		}
		return fmt.Errorf("failed to set shared secret with '%s': %s (code: %d)",
			c.hostport, errorResponse.ErrorMessage(), errorResponse.ErrorCode())
	}

	setupResponse, err := protocol.ParseSetupResponse(responseCommon, c.conn)
	if err != nil {
		return fmt.Errorf("failed to parse setup response from '%s': %w", c.hostport, err)
	}

	hashType := setupResponse.HashType()
	signature := setupResponse.Signature()
	setupResponse.SetSignature(0, nil) // clear the response before verifying the signature

	validSignature, err := serverPublicKey.VerifySignature(hashType.CryptoHash(), setupResponse.Bytes(), signature)
	if err != nil {
		return fmt.Errorf("failed to verify signature of setup response from '%s': %w", c.hostport, err)
	} else if !validSignature {
		return fmt.Errorf("failed to verify signature of setup response from '%s'", c.hostport)
	}

	secret, err := clientPrivateKey.ECDH(setupResponse.PublicKey())
	if err != nil {
		return fmt.Errorf("failed to generate shared secret: %w", err)
	}

	c.secret = secret
	c.id = id
	return nil
}

// Read reads data from the server.
func (c *Client) Read(p []byte) (int, error) {
	if c.readTimeout > 0 {
		referenceTime := time.Now()
		if err := c.conn.SetReadDeadline(referenceTime.Add(c.readTimeout)); err != nil {
			return 0, fmt.Errorf("failed to set connection read deadline: %w", err)
		}
	}

	// read data from buffer
	if c.buffer.Len() > 0 {
		n, err := c.buffer.Read(p)
		if err != nil {
			return 0, fmt.Errorf("failed to read data from buffer: %w", err)
		}
		return n, func() error {
			if c.buffer.Len() == 0 {
				return io.EOF
			}
			return nil
		}()
	}

	responseCommon, err := protocol.ParseResponseCommon(c.conn)
	if err != nil {
		return 0, fmt.Errorf("failed to parse response from '%s': %w", c.hostport, err)
	}

	if !responseCommon.Success() {
		errorResponse, err := protocol.ParseErrorResponse(c.conn, responseCommon)
		if err != nil {
			return 0, fmt.Errorf("failed to parse error response from '%s': %w", c.hostport, err)
		}
		return 0, fmt.Errorf("failed to read data from '%s': %s (code: %d)",
			c.hostport, errorResponse.ErrorMessage(), errorResponse.ErrorCode())
	}

	response, err := protocol.ParseProcessResponse(c.conn, responseCommon)
	if err != nil {
		return 0, fmt.Errorf("failed to parse success response from '%s': %w", c.hostport, err)
	}

	aes, err := aes.NewCipher(c.secret)
	if err != nil {
		return 0, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return 0, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	encryptedMessage := response.Message()

	if len(encryptedMessage) < nonceSize {
		return 0, fmt.Errorf("failed to decrypt data from server: encrypted message is too short (got %d bytes)",
			len(encryptedMessage))
	}

	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]
	message, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt data from server: %w", err)
	}

	if n, err := c.buffer.Write(message); err != nil {
		return 0, fmt.Errorf("failed to write data to buffer: %w", err)
	} else if n != len(message) {
		return 0, fmt.Errorf("failed to write data to buffer: expected writing %d bytes but wrote %d bytes",
			len(message), n)
	}

	n, err := c.buffer.Read(p)
	if err != nil {
		return 0, fmt.Errorf("failed to read data from buffer: %w", err)
	}
	return n, func() error {
		if c.buffer.Len() == 0 {
			return io.EOF
		}
		return nil
	}()
}

// Write writes data to the server.
func (c *Client) Write(p []byte) (n int, err error) {
	if c.writeTimeout > 0 {
		referenceTime := time.Now()
		if err := c.conn.SetWriteDeadline(referenceTime.Add(c.writeTimeout)); err != nil {
			return 0, fmt.Errorf("failed to set connection write deadline: %w", err)
		}
	}

	aes, err := aes.NewCipher(c.secret)
	if err != nil {
		return 0, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return 0, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return c.conn.Write(protocol.NewProcessRequest(c.id, gcm.Seal(nonce, nonce, p, nil),
		protocol.WithProcessRequestExpectReply(c.expectReply),
	).Bytes())
}

// Close closes the connection with the server.
func (c *Client) Close() error {
	if c.pool != nil {
		return c.pool.put(c)
	}
	return c.close()
}

func (c *Client) close() error {
	err := c.conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection with '%s': %w", c.hostport, err)
	}
	c.buffer.Reset()
	return nil
}

// LocalAddr returns the local network address, if known.
func (c *Client) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address, if known.
func (c *Client) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// It is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations fail instead of
// blocking. The deadline applies to all future and pending I/O, not just the
// immediately following call to Read or Write. After a deadline has been
// exceeded, the connection can be refreshed by setting a deadline in the
// future.
//
// If the deadline is exceeded a call to Read or Write or to other I/O methods
// will return an error that wraps os.ErrDeadlineExceeded. This can be tested
// using errors.Is(err, os.ErrDeadlineExceeded). The error's Timeout method will
// return true, but note that there are other possible errors for which the
// Timeout method will return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending the deadline after
// successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *Client) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls and any
// currently-blocked Read call. A zero value for t means Read will not time out.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls and any
// currently-blocked Write call. Even if write times out, it may return n > 0,
// indicating that some of the data was successfully written. A zero value for t
// means Write will not time out.
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
