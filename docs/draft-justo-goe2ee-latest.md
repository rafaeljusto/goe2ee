---
title: "GoE2EE: An End-to-End Encryption Protocol with Flexible Server Key Retrieval"
abbrev: GoE2EE
docname: draft-justo-goe2ee-latest
category: info

ipr: trust200902
submissiontype: independent
area: Security
keyword:
  - Internet-Draft
  - end-to-end encryption
  - Diffie-Hellman
  - AEAD

stand_alone: yes
pi: [toc, tocindent, sortrefs, symrefs, strict, compact, comments, inline, docmapping]

venue:
  repo: https://github.com/rafaeljusto/goe2ee

author:
  ins: R. D. Justo
  name: Rafael Dantas Justo
  org: Teamwork.com
  email: rafael@justo.net.br
  country: Ireland

normative:
  RFC4122:
  RFC5280:
  RFC5869:
  RFC7748:
  RFC5116:
  NIST.SP.800-38D:
  FIPS.180-4:
    target: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
    title: Secure Hash Standard (SHS)
    author:
      org: National Institute of Standards and Technology
    date: 2015-08
    seriesinfo:
      FIPS: PUB 180-4
  FIPS.197:
    target: https://csrc.nist.gov/pubs/fips/197/final
    title: Advanced Encryption Standard (AES)
    author:
      org: National Institute of Standards and Technology
    date: 2001-11
    seriesinfo:
      FIPS: PUB 197

informative:
  RFC6479:
  RFC4033:
  RFC8484:
  RFC8032:
  RFC8017:

--- abstract

This document specifies GoE2EE, an application-layer protocol that provides
end-to-end confidentiality and integrity between a client and a server using an
ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange and an
Authenticated Encryption with Associated Data (AEAD) cipher. The protocol aims
to provide a security level comparable to TLS 1.3 while allowing a shared secret
to be reused across multiple connections originating from the same host,
reducing handshake overhead. GoE2EE runs over either TCP or UDP and offers
several strategies for a client to retrieve and authenticate the server's
long-term public key, including a strategy based on the DNSSEC chain of trust.

--- middle

# Introduction

Transport Layer Security (TLS) {{?RFC8446}} is the dominant protocol for
securing communication on the Internet. It couples confidentiality and
integrity with an authentication model that, in its most common deployment,
relies on the Web Public Key Infrastructure (PKI) and X.509 certificates
{{RFC5280}}.

GoE2EE is an application-layer protocol that provides similar cryptographic
guarantees to TLS 1.3 but decouples two concerns that TLS binds tightly
together:

1. how peers agree on a shared secret and encrypt traffic; and
2. how the client obtains and authenticates the server's long-term public key.

For the first concern, GoE2EE performs an ephemeral ECDH key exchange so that
the shared secret is never transmitted over the network, derives a symmetric key
from that secret, and protects every subsequent message with an AEAD cipher.

For the second concern, GoE2EE deliberately leaves the trust model pluggable. A
client MAY authenticate the server's public key through the Web PKI, through the
DNSSEC chain of trust, through a pre-provisioned key, or, when no authentication
is acceptable, by retrieving the key directly from the server in-band.

A distinguishing feature of GoE2EE is that a shared secret is bound to a
client-chosen identifier rather than to a single transport connection.
Consequently, several connections from the same host MAY reuse a previously
negotiated secret and skip the handshake entirely, which reduces latency and
allows the protocol to operate efficiently over connectionless transports such
as UDP.

This document specifies the wire format, the cryptographic constructions, the
handshake and message-exchange procedures, and the security considerations of
the protocol. It corresponds to protocol version 1.

## Requirements Language

{::boilerplate bcp14+}

## Terminology

The following terms are used throughout this document:

Client:
: The peer that initiates a session and originates request messages.

Server:
: The peer that answers requests and holds a long-term signing key pair.

Global key:
: The server's long-term ("global") signing key pair. The server's public
  global key is used by the client to authenticate the handshake.

Session identifier (id):
: A 16-octet identifier chosen by the client and associated with a shared
  secret. It is carried in requests so that the server can locate the
  corresponding secret.

Shared secret:
: The secret produced by the ECDH exchange, from which the symmetric key is
  derived.

Counter:
: A per-secret, strictly increasing 64-bit value used to derive AEAD nonces and
  to detect replays.

# Protocol Overview

A GoE2EE session has two logical phases: a handshake phase and a
message-exchange phase.

During the handshake, the client generates an ephemeral ECDH key pair, chooses a
session identifier, and sends its public key to the server (the Setup action,
{{setup}}). The server generates its own ephemeral ECDH key pair, computes the
shared secret, and returns its public key together with a signature over the
handshake transcript produced with the server's long-term global key. The client
verifies the signature using the server's public global key, which it obtained
beforehand through one of the retrieval strategies in {{key-retrieval}}, and then
computes the same shared secret.

The full handshake is illustrated below.

~~~ ascii-art
client                                             server
  |                                                  |
  |-- Setup: id + client ECDH public key ----------->|
  |                             (compute shared       |
  |                              secret, store by id) |
  |<-- Setup response: server ECDH public key + ------|
  |    hash-type + signature over transcript          |
  | (verify signature,                                |
  |  compute shared secret)                           |
  |                                                  |
  |== Process: id + counter + encrypted message ====>|
  |<===== Process response: counter + encrypted ======|
  |                                                  |
~~~
{: title="Full handshake followed by message exchange." }

Because the shared secret is indexed by the session identifier and not by the
transport connection, a different connection from the same host that already
knows a valid secret and identifier MAY skip the handshake and issue Process
requests ({{process}}) directly.

~~~ ascii-art
client                                             server
  |                                                  |
  |== Process: id + counter + encrypted message ====>|
  |<===== Process response: counter + encrypted ======|
  |                                                  |
~~~
{: title="Message exchange reusing a previously negotiated secret." }

The server MUST maintain the mapping from session identifier to shared secret
(and the associated replay state, {{replay}}) for as long as it is willing to
accept messages for that session, which MAY outlive any individual transport
connection. The mechanism and lifetime of this state are implementation
choices.

# Message Format

All messages are binary. Multi-octet integers are encoded in network byte order
(big-endian) unless stated otherwise.

## Request Header

Every request begins with a single octet whose two 4-bit fields are the protocol
version and the action:

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 ...
+-------+-------+---------------------------+
|version|action | message (variable)        |
+-------+-------+---------------------------+
~~~
{: title="Request header." }

version (4 bits):
: The protocol version. This document specifies version 1 (`0x1`). Up to 16
  versions can be expressed.

action (4 bits):
: An identifier that selects the request semantics. Up to 16 actions can be
  expressed. This document defines the actions in {{action-registry}}.

message (variable):
: Action-specific content. It MAY be empty.

The fixed one-octet header, together with session identifiers carried inside
Process requests, is what allows a client to issue actions in any order and to
skip the handshake when a secret is already established.

The defined actions are:

| Action | Name      | Section     |
|--------|-----------|-------------|
| `0x1`  | Hello     | {{hello}}   |
| `0x2`  | Setup     | {{setup}}   |
| `0x3`  | Process   | {{process}} |
| `0x4`  | Fetch Key | {{fetch-key}} |
{: #action-registry title="Actions defined in version 1."}

A server that receives a request whose version it does not support MUST reply
with an error response ({{error-response}}) carrying error code
`0x04` (Unsupported version).

## Success Response

When a request is processed successfully, the response begins with a single
octet whose most significant bit is set to 1:

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 ...
+-+-------------+---------------------------+
|1| reserved    | message (variable)        |
+-+-------------+---------------------------+
~~~
{: title="Success response header." }

success (1 bit):
: Set to 1 to indicate success.

reserved (7 bits):
: Reserved for future use. A sender MUST set these bits to 0 and a receiver
  MUST ignore them.

message (variable):
: Action-specific content. It MAY be empty.

## Error Response {#error-response}

Any request MAY produce an error response. An error response begins with a
single octet whose most significant bit is cleared to 0, followed by an error
code and an optional human-readable message:

~~~
+---+----------+--------------+--------------+---------------+
| 0 | resv (7) | err-code (4) | err-size (8) | err-msg (var) |
+---+----------+--------------+--------------+---------------+
~~~
{: title="Error response. resv = reserved bits, err = error, msg = message. Field widths in octets except where noted." }

success (1 bit):
: Cleared to 0 to indicate failure.

reserved (7 bits):
: Reserved for future use; set to 0 on transmit and ignored on receipt.

error-code (4 octets):
: An unsigned 32-bit integer identifying the error. Defined values appear in
  {{error-registry}}.

error-message-size (8 octets):
: An unsigned 64-bit integer giving the length in octets of the error message.

error-message (variable):
: A UTF-8 diagnostic string of the indicated length. It MAY be empty and MUST
  NOT be relied upon for automated decision-making.

The defined error codes are:

| Error Code   | Description         |
|--------------|---------------------|
| `0x00000001` | Malformed request   |
| `0x00000002` | Server error        |
| `0x00000003` | Unknown client      |
| `0x00000004` | Unsupported version |
| `0x00000005` | Replay detected     |
{: #error-registry title="Error codes defined in version 1."}

A receiver MUST treat an error message whose declared size would exceed the
receiver's configured limits as a malformed response and abort the session. See
{{dos}}.

# Cryptographic Constructions

## Key Exchange

The ephemeral key exchange uses ECDH with the X25519 function {{RFC7748}}.
Public keys are exchanged encoded as a SubjectPublicKeyInfo structure in PKIX,
ASN.1 DER form ({{Section 4.1 of RFC5280}}).

Each peer generates a fresh X25519 key pair for every handshake. The shared
secret is the X25519 output computed from one peer's private key and the other
peer's public key.

## Key Derivation

The raw ECDH output MUST NOT be used directly as a symmetric key, as it is not
uniformly distributed. The symmetric key is derived using HKDF {{RFC5869}} with
SHA-256 {{FIPS.180-4}} as follows:

~~~
key = HKDF-SHA256(salt = "" (empty),
                  IKM  = ECDH shared secret,
                  info = "goe2ee/v1 aes-256-gcm",
                  L    = 32)
~~~

The `info` string provides domain separation and MUST be exactly the ASCII
string `goe2ee/v1 aes-256-gcm` for this version. The salt is empty (a string of
zero length). The output length L is 32 octets, producing a 256-bit key.

## Authenticated Encryption

Messages are protected with AES-256-GCM {{FIPS.197}} {{NIST.SP.800-38D}}, an
AEAD algorithm {{RFC5116}}, keyed with the 32-octet key from the previous
section. The authentication tag is 16 octets and is appended to the ciphertext.
The Associated Data is empty in this version.

## Nonce Derivation {#nonce}

AES-GCM requires that a (key, nonce) pair never repeat. GoE2EE never transmits
nonces; instead each peer derives the 12-octet GCM nonce deterministically from
a direction octet and the message counter:

~~~
nonce[0]      = direction
nonce[1..3]   = 0x00 0x00 0x00
nonce[4..11]  = counter (64-bit, big-endian)
~~~

where the direction octet is:

| Value  | Direction          |
|--------|--------------------|
| `0x00` | client to server   |
| `0x01` | server to client   |
{: title="Nonce direction octets."}

The direction octet ensures that the two halves of a conversation never derive
the same nonce from the same counter under the shared secret. The counter MUST
strictly increase for every message a peer sends under a given secret (see
{{counter-rules}}). Together these guarantee nonce uniqueness, which is required
for the security of AES-GCM.

## Handshake Transcript Signature {#transcript}

The server authenticates the handshake by signing a transcript that binds both
ephemeral public keys and the session identifier. The transcript is the
concatenation:

~~~
+----------+------------+----------+------------+---------+
| clen (4) | client-key | slen (4) | server-key | id (16) |
+----------+------------+----------+------------+---------+
~~~
{: title="Handshake transcript. clen/slen = client/server key size. Field widths in octets except where noted." }

where `client-key` and `server-key` are the DER-encoded SubjectPublicKeyInfo
representations of the client and server ephemeral public keys, each prefixed by
its 32-bit big-endian length, and `id` is the 16-octet session identifier.

Signing the full transcript rather than the server key alone binds the signature
to both parties and to the specific session, so a valid signature cannot be
transplanted onto a different key exchange.

The signature is produced with the server's long-term global key. The signature
algorithm depends on the type of the global key ({{key-registry}}):

* RSA keys: RSASSA-PKCS1-v1_5 {{RFC8017}} over the hash of the transcript.
* ECDSA keys: ECDSA over the hash of the transcript, with the signature encoded
  as an ASN.1 DER sequence.
* Ed25519 keys: Ed25519 {{RFC8032}} over the transcript. Note that for Ed25519
  the hash type carried in the response ({{setup}}) selects the digest applied
  to the transcript before signing; the pure Ed25519 algorithm is used (not
  Ed25519ph).

The hash function used to build the digest is signalled by the hash-type field
of the Setup response:

| Type  | Hash    |
|-------|---------|
| `0x2` | SHA-256 |
| `0x3` | SHA-384 |
| `0x4` | SHA-512 |
{: #hash-registry title="Hash types."}

SHA-1 is intentionally omitted because it is cryptographically broken. A client
MUST reject a Setup response that specifies a hash type it does not support.

# Actions

## Hello {#hello}

The Hello action is a liveness check. It carries no message body.

Request:

~~~
+-------+-------+
|  0x1  |  0x1  |
+-------+-------+
~~~

Response: a success response ({{error-response}} defines the failure form) with
an empty message body.

## Setup {#setup}

The Setup action performs the key exchange. The client sends its session
identifier and ephemeral public key; the server replies with its ephemeral
public key and a signature over the transcript ({{transcript}}).

Request:

~~~
+-----+-----+---------+-----------+------------+
| 0x1 | 0x2 | id (16) | pklen (4) | public-key |
+-----+-----+---------+-----------+------------+
~~~
{: title="Setup request. pklen = public-key size. Field widths in octets except where noted." }

id (16 octets):
: A client-chosen identifier for the secret, formatted as a UUID {{RFC4122}}.
  It MUST be unique per host so that the server can distinguish concurrent
  sessions from the same host, including those traversing intermediaries such
  as proxies. The client SHOULD choose it so that it is unpredictable to other
  parties.

public-key-size (4 octets):
: The length in octets of the following public key.

public-key (variable):
: The client's ephemeral X25519 public key, DER-encoded SubjectPublicKeyInfo.

Response:

~~~
+---+------+-----------+--------+-----------+------------+-----+
| 1 | resv | pklen (4) | pubkey | htype (1) | siglen (8) | sig |
+---+------+-----------+--------+-----------+------------+-----+
~~~
{: title="Setup response. pklen = public-key size, htype = hash-type, siglen = signature size, sig = signature. Field widths in octets except where noted." }

public-key-size (4 octets):
: The length in octets of the server's public key.

public-key (variable):
: The server's ephemeral X25519 public key, DER-encoded SubjectPublicKeyInfo.

hash-type (1 octet):
: The hash used to build the signed digest ({{hash-registry}}).

signature-size (8 octets):
: The length in octets of the signature.

signature (variable):
: The signature over the handshake transcript ({{transcript}}), produced with
  the server's global key.

On receiving the Setup response, the client MUST rebuild the transcript from its
own public key, the server's public key, and the session identifier, and MUST
verify the signature using the server's public global key. If verification
fails, the client MUST abort the session and MUST NOT send Process requests for
that identifier. On success, the client computes the shared secret from its
private key and the server's public key.

## Process {#process}

The Process action exchanges application data protected by the shared secret.

Request:

~~~
+-----+-----+---+------+---------+---------+----------+---------+
| 0x1 | 0x3 | E | r(7) | id (16) | ctr (8) | mlen (8) | enc-msg |
+-----+-----+---+------+---------+---------+----------+---------+
~~~
{: title="Process request. E = expect-reply flag, r = reserved flags, ctr = counter, mlen = encrypted-message size, enc-msg = encrypted message. Field widths in octets except where noted." }

E (expect-reply, 1 bit):
: When set to 1, the client expects a response. When cleared to 0, the request
  is fire-and-forget and the server SHOULD NOT send a response. This is useful
  over UDP to avoid a return trip.

reserved-flags (7 bits):
: Reserved for future use; set to 0 on transmit and ignored on receipt.

id (16 octets):
: The session identifier chosen during Setup, identifying the shared secret.

counter (8 octets):
: The per-secret message counter (see {{counter-rules}}), used both to derive the
  nonce ({{nonce}}) and to detect replays ({{replay}}).

encrypted-message-size (8 octets):
: The length in octets of the ciphertext (including the AEAD tag).

encrypted-message (variable):
: The application payload encrypted with AES-256-GCM under the derived key,
  using the nonce derived from direction `0x00` and this counter.

If the server does not recognise the identifier, it MUST reply with error code
`0x03` (Unknown client). If the counter is a replay or falls before the replay
window, the server MUST reply with error code `0x05` (Replay detected). If
decryption or tag verification fails, the server MUST treat the request as
malformed (`0x01`).

Response (sent only when E is set):

~~~
+-+----------+-----------+---------------------+---------------+
|1| reserved |counter (8)| enc-msg-size (8)    | enc-msg (var) |
+-+----------+-----------+---------------------+---------------+
~~~
{: title="Process response. Field widths in octets except where noted." }

counter (8 octets):
: The counter from the request being answered. The server derives the response
  nonce from direction `0x01` and this counter.

encrypted-message-size (8 octets):
: The length in octets of the response ciphertext (including tag).

encrypted-message (variable):
: The response payload encrypted under the same shared secret.

### Counter Rules {#counter-rules}

The counter is a property of the shared secret, not of a transport connection.
A client MUST ensure that every Process request it sends under a given secret
carries a strictly greater counter than any previous request under that secret.
When a secret is shared across several connections from the same host (see
{{reuse}}), the counter MUST be incremented atomically so that no value is ever
reused across those connections.

The server echoes the request counter in the response and derives the response
nonce from it with the server-to-client direction octet. Because request and
response use different direction octets, the same counter value in both
directions does not cause a nonce collision.

## Fetch Key {#fetch-key}

The Fetch Key action lets a client retrieve the server's public global key
in-band. This method provides no authentication of the key and is therefore
vulnerable to man-in-the-middle attacks; it MUST NOT be used when an
authenticated retrieval strategy ({{key-retrieval}}) is available.

Request:

~~~
+-------+-------+
|  0x1  |  0x4  |
+-------+-------+
~~~

Response:

~~~
+---+------+------------+-----------+------------+
| 1 | resv | keyalg (1) | pklen (4) | public-key |
+---+------+------------+-----------+------------+
~~~
{: title="Fetch Key response. keyalg = key-algorithm, pklen = public-key size. Field widths in octets except where noted." }

key-algorithm (1 octet):
: The algorithm of the returned key, used to parse it ({{key-registry}}).

public-key-size (4 octets):
: The length in octets of the public key.

public-key (variable):
: The server's public global key.

The defined key algorithms are:

| Algorithm | Description |
|-----------|-------------|
| `0x1`     | RSA         |
| `0x2`     | ECDSA       |
| `0x3`     | Ed25519     |
{: #key-registry title="Global key algorithms."}

# Server Public Key Retrieval {#key-retrieval}

The security of the handshake rests on the client authenticating the server's
public global key. This document does not mandate a single trust model; it
defines the following strategies, of which a client MUST use an authenticated
one unless the deployment explicitly accepts the risk of an unauthenticated key:

DNSSEC:
: The client retrieves the key from a DNSKEY resource record of the server's
  domain name and validates it through the DNSSEC chain of trust {{RFC4033}}.
  To protect the resolution path between the client and the recursive resolver,
  the client SHOULD use DNS over HTTPS {{RFC8484}}.

Web PKI:
: The client obtains an X.509 certificate {{RFC5280}} for the server, for
  example over an HTTPS connection to the server's domain, and validates it
  against a trusted certification authority.

Pre-provisioned:
: The key is provided to the client out of band, for example as a PEM file.

In-band (Fetch Key):
: The client retrieves the key using the Fetch Key action ({{fetch-key}}). This
  strategy is unauthenticated and is NOT RECOMMENDED.

The choice of strategy is a local deployment decision and does not affect the
wire format of the handshake.

# Secret Reuse and Connection Pooling {#reuse}

Because a shared secret is bound to a session identifier rather than to a
transport connection, a client MAY reuse an established secret for multiple
connections to the same host and MAY skip the handshake on those connections,
issuing Process requests directly. This reduces both round trips and
cryptographic work.

A client that reuses a secret across connections MUST coordinate the counter as
described in {{counter-rules}} so that nonces are never reused. Implementations
that pool connections SHOULD share a single counter, incremented atomically, per
secret.

The server retains the association between identifier, shared secret, and replay
state independently of any connection, so it can serve Process requests for a
known identifier that arrive on a fresh connection.

# Transport Considerations

GoE2EE operates over either TCP or UDP. Over TCP, the transport provides
ordering and delivery guarantees. Over UDP, the protocol imposes none: messages
may be lost, reordered, or duplicated.

The replay window ({{replay}}) tolerates limited reordering, and the
deterministic nonce derivation ({{nonce}}) does not require in-order delivery.
The fire-and-forget mode of the Process action ({{process}}) is particularly
suited to UDP, where avoiding a return trip can significantly reduce overhead
for small payloads.

Applications that require reliable, ordered delivery SHOULD use TCP or provide
their own reliability layer above GoE2EE.

# Security Considerations

## Server Authentication and Trust Model

The confidentiality of a GoE2EE session depends entirely on the client
authenticating the server's public global key before trusting the handshake
signature. If a client accepts an unauthenticated key -- notably one obtained
through the Fetch Key action ({{fetch-key}}) -- an active attacker can mount a
man-in-the-middle attack, presenting its own key and relaying or reading all
traffic. Deployments SHOULD use an authenticated retrieval strategy
({{key-retrieval}}).

## Handshake Integrity

The server signs a transcript ({{transcript}}) that includes both ephemeral
public keys and the session identifier. This binds the signature to the specific
key exchange and session, preventing a signature captured from one handshake
from being replayed into another. The client MUST verify this signature and MUST
abort on failure.

The protocol as specified does not authenticate the client to the server at the
cryptographic layer; any client that can present a valid identifier and correctly
encrypted messages will be served. Deployments that require client
authentication MUST provide it at the application layer or by another mechanism.

## Nonce Uniqueness

AES-GCM catastrophically fails if a (key, nonce) pair is ever reused: an
attacker who observes two messages encrypted with the same key and nonce can
recover the authentication subkey and forge messages {{NIST.SP.800-38D}}.
GoE2EE relies on the strictly increasing per-secret counter and the direction
octet ({{nonce}}) to guarantee uniqueness. Implementations MUST ensure the
counter never repeats or goes backwards for a given secret, including across
pooled connections ({{counter-rules}}), and MUST stop using a secret before the
64-bit counter would wrap.

## Replay Protection {#replay}

The server maintains, per secret, a sliding-window replay filter in the style of
the IPsec anti-replay algorithm {{RFC6479}}. The window tracks the highest
counter seen and a bitmap of the 64 counter values immediately below it. A
message is accepted only if its counter has not been seen before and is not older
than the window; otherwise the server rejects it with error code `0x05` (Replay
detected). This bounds the reordering the server tolerates over unreliable
transports while preventing an attacker from replaying captured Process
requests.

Because replay state is per secret and outlives connections, an implementation
that reuses a secret across connections shares one replay window for all of
them, consistent with the shared counter requirement.

## Forward Secrecy

Each handshake uses fresh ephemeral X25519 key pairs, so the compromise of a
server's long-term global key does not by itself reveal the shared secrets of
past sessions. However, reusing a shared secret across many connections
({{reuse}}) enlarges the amount of data protected by a single key and the impact
of that secret's compromise. Deployments SHOULD bound the lifetime and volume of
data associated with any single secret and re-run the handshake periodically.

## Denial of Service {#dos}

Several fields are length-prefixed with sizes up to 64 bits. A malicious peer
could advertise an enormous size to force large allocations. Implementations
MUST enforce sane upper bounds on the sizes of public keys, signatures, and
encrypted messages before allocating, and MUST reject messages that exceed those
bounds as malformed. The server also holds per-secret state indexed by
client-chosen identifiers; an implementation SHOULD bound the number of
concurrent sessions and expire idle state to limit memory exhaustion.

## Downgrade and Versioning

The version field ({{action-registry}}) allows future evolution. A server MUST
reject unsupported versions (`0x04`). Because the version and action occupy a
single unauthenticated header octet at the start of each request, deployments
concerned with downgrade across versions SHOULD ensure that any future version
that changes the cryptographic constructions also changes the HKDF `info` label
so that keys are not shared across versions.

# IANA Considerations

This document has no IANA actions.

The actions ({{action-registry}}), error codes ({{error-registry}}), hash types
({{hash-registry}}), and key algorithms ({{key-registry}}) defined here are
namespaces internal to the protocol and are not requested for registration in
any IANA registry by this document. Should this protocol be standardized, the
creation of IANA registries for these code points would be appropriate.

--- back

# Acknowledgements
{: numbered="false"}

The design of GoE2EE draws on the architecture of TLS 1.3 {{RFC8446}} and on
established constructions for key derivation {{RFC5869}}, authenticated
encryption {{NIST.SP.800-38D}}, and anti-replay {{RFC6479}}.
