# goe2ee

[![Go Reference](https://pkg.go.dev/badge/github.com/rafaeljusto/goe2ee.svg)](https://pkg.go.dev/github.com/rafaeljusto/goe2ee)
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
[here](https://github.com/rafaeljusto/goe2ee/blob/main/protocol/README.md).

## ⚡️ Quick start

You can use `go get` to add this library to your project:
```
go get github.com/rafaeljusto/goe2ee
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

For the client side, the fastest approach would be using all the default
configurations, which includes validating the server's public key using the
DNSSEC chain of trust:
```go
client, err := goe2ee.DialTCP("goe2ee-server.example.com:60323")
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

You can find more complex examples [here](examples).