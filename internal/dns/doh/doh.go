// Package doh provides a DNS-over-HTTPS client. This package does not implement
// RFC 8484 that relies on DNS wire format instead of JSON. It is a simple
// implementation that works with Google and Cloudflare providers.
package doh

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rafaeljusto/goe2ee/internal/dns/dnssec"
)

// DNSOverHTTPSOptions are the options used to configure the DNS-over-HTTPS. You
// cannot modify the properties directly, instead use auxiliary functions when
// initializing DNSOverHTTPS type.
type DNSOverHTTPSOptions struct {
	timeout time.Duration
}

// WithDNSOverHTTPSTimeout configures the timeout used when resolving DNS via
// HTTPS. By default it will use 5 seconds.
func WithDNSOverHTTPSTimeout(dnsTimeout time.Duration) func(*DNSOverHTTPSOptions) {
	return func(options *DNSOverHTTPSOptions) {
		options.timeout = dnsTimeout
	}
}

// DNSOverHTTPS is a DNS-over-HTTPS client relying on providers that support
// application/dns-json (RFC 8427 [1]).
//
// [1] https://www.rfc-editor.org/rfc/rfc8427.html
type DNSOverHTTPS struct {
	provider string
	client   http.Client
}

// NewDNSOverHTTPS creates a new DNS-over-HTTPS client.
func NewDNSOverHTTPS(provider string, optFuncs ...func(*DNSOverHTTPSOptions)) *DNSOverHTTPS {
	options := DNSOverHTTPSOptions{
		timeout: 5 * time.Second,
	}
	for _, f := range optFuncs {
		f(&options)
	}
	return &DNSOverHTTPS{
		provider: provider,
		client: http.Client{
			Timeout: options.timeout,
		},
	}
}

// RetrievePublicKey retrieves the server's public key using DNS-over-HTTPS.
func (d *DNSOverHTTPS) RetrievePublicKey(domain string) (crypto.PublicKey, error) {
	request, err := http.NewRequest(http.MethodGet, d.provider, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS over HTTPS for provider '%s': %w", d.provider, err)
	}

	query := request.URL.Query()
	query.Add("name", domain)
	query.Add("type", "DNSKEY")

	request.URL.RawQuery = query.Encode()
	request.Header.Set("Accept", "application/dns-json")

	response, err := d.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS over HTTPS request '%s': %w", request.URL.String(), err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS over HTTPS request '%s' returned status code %d",
			request.URL.String(), response.StatusCode)
	}

	var jsonAPI dnsOverHTTPSJSONAPI
	jsonDecoder := json.NewDecoder(response.Body)
	if err := jsonDecoder.Decode(&jsonAPI); err != nil {
		return nil, fmt.Errorf("failed to decode DNS over HTTPS response '%s': %w",
			request.URL.String(), err)
	}

	if len(jsonAPI.Answers) == 0 {
		return nil, fmt.Errorf("DNS over HTTPS request '%s' returned no answers",
			request.URL.String())
	}

	var publicKey crypto.PublicKey
	for _, answer := range jsonAPI.Answers {
		publicKey, err = dnssec.ParseDNSKEY(answer.Data)
		if err != nil {
			continue
		}
		if publicKey != nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if publicKey == nil {
		return nil, fmt.Errorf("no valid DNSKEY found for domain '%s'", domain)
	}
	return publicKey, nil
}

type dnsOverHTTPSJSONAPI struct {
	Answers []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}
