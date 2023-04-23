package key

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	internaldoh "github.com/rafaeljusto/goe2ee/internal/dns/doh"
	internalnet "github.com/rafaeljusto/goe2ee/internal/net"
	"github.com/rafaeljusto/goe2ee/protocol"
)

const (
	// GoogleDNSProvider is a DNS-over-HTTPS server.
	//
	// https://developers.google.com/speed/public-dns/docs/dns-over-https
	GoogleDNSProvider = "https://dns.google/resolve"
	// CloudflareDNSProvider is a DNS-over-HTTPS server.
	//
	// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/
	CloudflareDNSProvider = "https://1.1.1.1/dns-query"
)

// ClientFetcher is a generic interface to allow fetching the server's public
// key from different sources.
type ClientFetcher interface {
	Fetch(host string) (PublicKey, error)
}

// make sure ClientFetcherDNSKEY implements ClientFetcher.
var _ ClientFetcher = ClientFetcherDNSKEY{}

// ClientFetcherDNSKEYOptions contains options for the KeyFetcherDNSKEY
// constructor.
type ClientFetcherDNSKEYOptions struct {
	timeout time.Duration
}

// ClientFetcherDNSKEYWithTimeout sets the timeout for the DNS over HTTPS
// request. By default it will use 5 seconds.
func ClientFetcherDNSKEYWithTimeout(timeout time.Duration) func(*ClientFetcherDNSKEYOptions) {
	return func(options *ClientFetcherDNSKEYOptions) {
		options.timeout = timeout
	}
}

// ClientFetcherDNSKEY retrieves the server's public key in the DNSKEY resource
// record using DNS over HTTPS. It's highly recommended to wrap this fetcher in
// a cache (ClientFetcherCache) to avoid network overheads on every handshake.
//
// It supports DNSKEY containing RSA, ECDSA and Ed25519 keys.
type ClientFetcherDNSKEY struct {
	provider string
	timeout  time.Duration
}

// NewClientFetcherDNSKEY creates a new ClientFetcherDNSKEY.
func NewClientFetcherDNSKEY(provider string, optFuncs ...func(*ClientFetcherDNSKEYOptions)) ClientFetcherDNSKEY {
	options := ClientFetcherDNSKEYOptions{
		timeout: 5 * time.Second,
	}
	for _, f := range optFuncs {
		f(&options)
	}
	return ClientFetcherDNSKEY{
		provider: provider,
		timeout:  options.timeout,
	}
}

// Fetch retrieves the server's public key in the DNSKEY resource record.
func (c ClientFetcherDNSKEY) Fetch(host string) (PublicKey, error) {
	// retrieve server's public key using DNS over HTTPS
	dnsOverHTTPS := internaldoh.NewDNSOverHTTPS(c.provider, internaldoh.WithDNSOverHTTPSTimeout(c.timeout))
	publicKey, err := dnsOverHTTPS.RetrievePublicKey(host)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{PublicKey: publicKey}, nil
}

// make sure ClientFetcherTLS implements ClientFetcher.
var _ ClientFetcher = ClientFetcherTLS{}

// ClientFetcherTLSOptions contains options for the ClientFetcherTLS.
type ClientFetcherTLSOptions struct {
	tlsPort uint64
	rootCAs *x509.CertPool
}

// ClientFetcherTLSWithPort sets the port to use when connecting to the server.
// By default it will use 443.
func ClientFetcherTLSWithPort(port uint64) func(*ClientFetcherTLSOptions) {
	return func(options *ClientFetcherTLSOptions) {
		options.tlsPort = port
	}
}

// ClientFetcherTLSWithRootCAs sets the root CAs to use when verifying the TLS
// certificate. By default it will use the host's root CA set.
func ClientFetcherTLSWithRootCAs(rootCAs *x509.CertPool) func(*ClientFetcherTLSOptions) {
	return func(options *ClientFetcherTLSOptions) {
		options.rootCAs = rootCAs
	}
}

// ClientFetcherTLS retrieves the server's public key in the TLS certificate.
// It's highly recommended to wrap this fetcher in a cache (ClientFetcherCache)
// to avoid network overheads on every handshake.
type ClientFetcherTLS struct {
	tlsPort uint64
	rootCAs *x509.CertPool
}

// NewClientFetcherTLS creates a new FetcherTLS.
func NewClientFetcherTLS(optFuncs ...func(*ClientFetcherTLSOptions)) ClientFetcherTLS {
	options := ClientFetcherTLSOptions{
		tlsPort: 443,
	}
	for _, f := range optFuncs {
		f(&options)
	}
	return ClientFetcherTLS(options)
}

// Fetch retrieves the server's public key in the TLS certificate. It will use
// host's root CA set to verify the certificate.
func (c ClientFetcherTLS) Fetch(host string) (publicKey PublicKey, err error) {
	var conn *tls.Conn
	conn, err = tls.Dial("tcp", host+":"+strconv.FormatUint(c.tlsPort, 10), &tls.Config{
		RootCAs: c.rootCAs,
	})
	if err != nil {
		return
	}
	defer func() {
		if connErr := conn.Close(); connErr != nil {
			err = errors.Join(err, connErr)
		}
	}()
	err = conn.VerifyHostname(host)
	if err != nil {
		return
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	if cert.NotAfter.Before(time.Now()) {
		err = errors.New("certificate is not valid yet")
		return
	}
	if cert.NotBefore.After(time.Now()) {
		err = errors.New("certificate has expired")
		return
	}
	publicKey.PublicKey = cert.PublicKey
	return
}

// make sure ClientFetcherProtocol implements ClientFetcher.
var _ ClientFetcher = ClientFetcherProtocol{}

// ClientFetcherProtocol retrieves the server's public key using the goe2ee
// protocol. This fetcher could be vulnerable to man-in-the-middle attacks. It's
// highly recommended to wrap this fetcher in a cache (ClientFetcherCache) to
// avoid network overheads on every handshake.
type ClientFetcherProtocol struct {
	network    string
	serverAddr string
}

// NewClientFetcherProtocol creates a new ClientFetcherProtocol.
func NewClientFetcherProtocol(network, serverAddr string) ClientFetcherProtocol {
	return ClientFetcherProtocol{
		network:    network,
		serverAddr: serverAddr,
	}
}

// Fetch retrieves the server's public key using the goe2ee protocol.
func (c ClientFetcherProtocol) Fetch(_ string) (PublicKey, error) {
	var conn io.ReadWriter
	switch c.network {
	case "tcp":
		tcpAddr, err := net.ResolveTCPAddr("tcp", c.serverAddr)
		if err != nil {
			return PublicKey{}, err
		}

		tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return PublicKey{}, err
		}
		defer func() {
			_ = tcpConn.Close()
		}()
		conn = tcpConn

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
		if err != nil {
			return PublicKey{}, err
		}

		udpConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return PublicKey{}, err
		}
		defer func() {
			_ = udpConn.Close()
		}()
		conn = internalnet.NewUDPConn(udpConn,
			internalnet.WithUDPConnBufferedWrite(false),
		)

	default:
		return PublicKey{}, fmt.Errorf("network %q not supported", c.network)
	}

	_, err := conn.Write(protocol.NewFetchKeyRequest().Bytes())
	if err != nil {
		return PublicKey{}, err
	}

	responseCommon, err := protocol.ParseResponseCommon(conn)
	if err != nil {
		return PublicKey{}, err
	}
	if !responseCommon.Success() {
		responseError, err := protocol.ParseErrorResponse(conn, responseCommon)
		if err != nil {
			return PublicKey{}, err
		}
		return PublicKey{}, fmt.Errorf("error response (%d): %s", responseError.ErrorCode(), responseError.ErrorMessage())
	}

	response, err := protocol.ParseFetchKeyResponse(conn, responseCommon)
	if err != nil {
		return PublicKey{}, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey())
	if err != nil {
		return PublicKey{}, fmt.Errorf("error parsing public key: %w", err)
	}
	return PublicKey{PublicKey: publicKey}, nil
}

// make sure ClientFetcherPEMFile implements ClientFetcher.
var _ ClientFetcher = ClientFetcherInMemory{}

// ClientFetcherInMemory retrieves the server's public key from an in-memory
// storage.
type ClientFetcherInMemory struct {
	publicKey PublicKey
}

// NewClientFetcherInMemory creates a new ClientFetcherInMemory from a public
// key.
func NewClientFetcherInMemory(publicKey PublicKey) ClientFetcherInMemory {
	return ClientFetcherInMemory{
		publicKey: publicKey,
	}
}

// ParseClientFetcherPEM creates a new ClientFetcherPEM.
func ParseClientFetcherPEM(r io.Reader) (*ClientFetcherInMemory, error) {
	pubPEMData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	return &ClientFetcherInMemory{
		publicKey: PublicKey{PublicKey: pub},
	}, nil
}

// Fetch retrieves the server's public key from a PEM file.
func (c ClientFetcherInMemory) Fetch(_ string) (PublicKey, error) {
	return c.publicKey, nil
}

// make sure ClientFetcherCache implements ClientFetcher.
var _ ClientFetcher = &ClientFetcherCache{}

// ClientFetcherCacheOptions contains options for the ClientFetcherCache.
type ClientFetcherCacheOptions struct {
	ttl time.Duration
}

// ClientFetcherCacheWithTTL sets the TTL for the cache. By default it will use
// 5 minutes.
func ClientFetcherCacheWithTTL(ttl time.Duration) func(*ClientFetcherCacheOptions) {
	return func(options *ClientFetcherCacheOptions) {
		options.ttl = ttl
	}
}

// ClientFetcherCache is a generic interface to allow fetching the server's
// public key from different sources. It will cache the public key for a given
// TTL.
type ClientFetcherCache struct {
	fetcher ClientFetcher
	cache   sync.Map
	ttl     time.Duration
}

// NewClientFetcherCache creates a new ClientFetcherCache.
func NewClientFetcherCache(fetcher ClientFetcher, optFuncs ...func(*ClientFetcherCacheOptions)) *ClientFetcherCache {
	type cacheItem struct {
		_        PublicKey
		storedAt time.Time
	}

	options := ClientFetcherCacheOptions{
		ttl: 5 * time.Minute,
	}
	for _, f := range optFuncs {
		f(&options)
	}

	c := ClientFetcherCache{
		fetcher: fetcher,
		ttl:     options.ttl,
	}
	if c.ttl > 0 {
		go func() {
			timeTicker := time.NewTicker(1 * time.Minute)
			defer timeTicker.Stop()

			for range timeTicker.C {
				c.cache.Range(func(key, value interface{}) bool {
					if item := value.(cacheItem); time.Since(item.storedAt) > c.ttl {
						c.cache.Delete(key)
					}
					return true
				})
			}
		}()
	}
	return &c
}

// Fetch retrieves the server's public key from the cache or from the underlying
// fetcher. If the public key is not in the cache, it will be fetched and stored
// in the cache.
func (c *ClientFetcherCache) Fetch(host string) (PublicKey, error) {
	type cacheItem struct {
		publicKey PublicKey
		storedAt  time.Time
	}

	if cached, ok := c.cache.Load(host); ok {
		return cached.(cacheItem).publicKey, nil
	}

	publicKey, err := c.fetcher.Fetch(host)
	if err != nil {
		return PublicKey{}, err
	}

	c.cache.Store(host, cacheItem{
		publicKey: publicKey,
		storedAt:  time.Now(),
	})
	return publicKey, nil
}
