# goe2ee

[![Go Reference](https://pkg.go.dev/badge/github.com/rafaeljusto/goe2ee/v2.svg)](https://pkg.go.dev/github.com/rafaeljusto/goe2ee/v2)
![Test](https://github.com/rafaeljusto/goe2ee/actions/workflows/test.yml/badge.svg)

End-to-end encryption (E2EE) library in Go language. Securely communicate with
your peer without ever exchanging a secret (Diffie–Hellman key exchange).

## ⚙️ Features

As part of the secure initial handshake, the client needs to retrieve the
server's public key. For protocols like TLS, it's required to validate this
public key using a certification authority, this library on the other hand gives
flexibility on how the client retrieves/validates the public key. You can use
pre-defined strategies or even implement your own.

It will make available out-of-the-box the following strategies:

* Use the DNSKEY resource record of the target domain name. The resource record
  should be trusted following the DNSSEC chain of trust. To make sure the
  resolution between the resolver and the recursive DNS is also safe the library
  will use DNS over HTTPS.

* Rely on an x509 certificate, validating against a certification authority. The
  certificate can be retrieved from an HTTPS connection with the target domain.

* Directly retrieve the key from the server using the protocol. This is not
  safe, as it can be vulnerable to man-in-the-middle attacks.

* Manually provided (PEM file).

Other benefits of this protocol:

* Use the same shared secret between connections of the same host. This saves
  time in the handshake process. The library already provides a client
  connection pool to better use this feature.

* Allow TCP or UDP connections. When working with small packages and don't mind
  about delivery guarantees, you could use UDP, which has less network overhead.

* Optionally bypass server response. This special flag allows the client to fire
  and forget, saving a network overhead.

Details about the protocol can be found
[here](https://github.com/rafaeljusto/goe2ee/blob/main/protocol/README.md). A
formal specification is also written up as an IETF Internet-Draft, published as
a [rendered web page](https://rafaeljusto.github.io/goe2ee/) with the source
under
[`docs/`](https://github.com/rafaeljusto/goe2ee/blob/main/docs/draft-justo-goe2ee-latest.md)
(also rendered as
[text](https://github.com/rafaeljusto/goe2ee/blob/main/docs/draft-justo-goe2ee-latest.txt)).

## ⚡️ Quick start

You can use `go get` to add this library to your project:
```
go get github.com/rafaeljusto/goe2ee/v2
```

When building a server the simplest setup would be the below. This example sends
back the same received content.
```go
server := goe2ee.NewServer(
  goe2ee.ServerHandlerFunc(goe2ee.ServerHandlerFunc(func(w io.Writer, r io.Reader, remoteAddr net.Addr) error {
    content, err := io.ReadAll(r)
    if err != nil {
      return err
    }
    _, err = w.Write(content)
    return err
  })),
)
defer func() {
  if err := server.Close(); err != nil {
    log.Printf("failed to close the server: %v", err)
  }
}()

addr, err := server.StartTCP(":60323")
if err != nil {
  log.Printf("failed to start tcp server: %v", err)
  return
}
```

For the client side, the quickest way to get a working connection is to fetch
the server's public key directly from the server over the protocol itself. This
needs no external infrastructure, so it's ideal for local development and trying
the library out:
```go
hostport := "localhost:60323"
client, err := goe2ee.DialTCP(hostport,
  goe2ee.ClientWithKeyFetcher(key.NewClientFetcherProtocol("tcp", hostport)),
)
if err != nil {
  log.Printf("failed to connect to server: %v", err)
  return
}
defer func() {
  if err := client.Close(); err != nil {
    log.Printf("failed to close client: %v", err)
  }
}()

if _, err := client.Write([]byte("hello")); err != nil {
  log.Printf("failed to send message: %v", err)
  return
}
response, err := io.ReadAll(client)
if err != nil {
  log.Printf("failed to read server's response: %v", err)
  return
}
```

> [!WARNING]
> For local development and testing only. Fetching the key over the protocol
> trusts whatever key the server (or a man-in-the-middle) hands back on first
> contact, so it provides no protection against an impersonated server. Do not
> use `ClientFetcherProtocol` in production.

For production you should validate the server's public key against a trusted
source. The default configuration does exactly that, using the `DNSKEY` resource
record of the target domain validated through the DNSSEC chain of trust (over
DNS-over-HTTPS). Once the server has published its key as a DNSSEC-signed
`DNSKEY` record, the client needs no key-fetcher configuration at all:
```go
client, err := goe2ee.DialTCP("goe2ee-server.example.com:60323")
if err != nil {
  log.Printf("failed to connect to server: %v", err)
  return
}
```

Alternatively you can validate the key against an x509 certificate
(`key.NewClientFetcherTLS()`) or provide it manually from a PEM file
(`key.ParseClientFetcherPEM(...)`). See the [features](#️-features) section for
the full list of strategies.

You can find more complex examples [here](examples).