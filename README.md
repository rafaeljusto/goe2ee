# goe2ee

[![Go Reference](https://pkg.go.dev/badge/github.com/rafaeljusto/goe2ee.svg)](https://pkg.go.dev/github.com/rafaeljusto/goe2ee)
![Test](https://github.com/rafaeljusto/goe2ee/actions/workflows/test.yml/badge.svg)

End-to-end encryption (E2EE) library in Go language. It will use Diffie–Hellman
key exchange to define the shared secret.

The library is flexible on how the client retrieves the public key. It will make
available out-of-the-box the following strategies:

* Use the DNSKEY resource record of the target domain name. The resource record
  should be trusted following the DNSSEC chain of trust. To make sure the
  resolution between the resolver and the recursive DNS is also safe the library
  will use DNS over HTTPS.

* Rely on an x509 certificate with validating against a certification authority.
  The certificate can be retrieved from an HTTPS connection with the target
  domain.

* Directly retrieve the key from the server using the protocol. This is not
  safe, as it can be vulnerable to man-in-the-middle attacks.

* Manually provided.

Other benefits of this protocol:

* Use the same shared secret between connections of the same host. This saves
  time in the handshake process. The library already provides a client
  connection pool to better use this feature.

* Allow TCP or UDP connections. When working with small packages and don't mind
  about delivery guarantees, you could use UDP, which has less network overhead.

* Optionally bypass server response. This special flag allows the client to fire
  and forget, saving a network overhead.

Details about the protocol can be found
[here](https://github.com/rafaeljusto/goe2ee/blob/main/protocol/README.md).