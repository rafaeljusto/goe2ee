// Package dnssec implements DNSSEC related functions. Most part of the code was
// copied or used as reference miekg/dns library.
//
// # BSD 3-Clause License
//
// Copyright (c) 2009, The Go Authors. Extensions copyright (c) 2011, Miek
// Gieben. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// DNSSEC encryption algorithm codes.
//
// https://github.com/miekg/dns/blob/a6f978594be8a97447dd1a5eab6df481c7a8d9dc/dnssec.go#L23
const (
	_ uint8 = iota
	algorithmRSAMD5
	algorithmDH
	algorithmDSA
	_ // Skip 4, RFC 6725, section 2.1
	algorithmRSASHA1
	algorithmDSANSEC3SHA1
	algorithmRSASHA1NSEC3SHA1
	algorithmRSASHA256
	_ // Skip 9, RFC 6725, section 2.1
	algorithmRSASHA512
	_ // Skip 11, RFC 6725, section 2.1
	algorithmECCGOST
	algorithmECDSAP256SHA256
	algorithmECDSAP384SHA384
	algorithmED25519
	algorithmED448
	algorithmIndirect   uint8 = 252
	algorithmPrivateDNS uint8 = 253 // Private (experimental keys)
	algorithmPrivateOID uint8 = 254
)

// ParseDNSKEY parses a DNSKEY record and returns the public key.
func ParseDNSKEY(key string) (crypto.PublicKey, error) {
	dnskeyParts := strings.Split(key, " ")
	if len(dnskeyParts) != 4 {
		return nil, fmt.Errorf("invalid DNSKEY format '%s'", key)
	}
	flags, err := strconv.ParseUint(dnskeyParts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY flags '%s': %w", dnskeyParts[0], err)
	}
	if flags != 256 {
		// ignore KSKs, we are only interested on ZSKs
		return nil, nil
	}
	protocol, err := strconv.ParseUint(dnskeyParts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY protocol '%s': %w", dnskeyParts[1], err)
	}
	if protocol != 3 {
		return nil, fmt.Errorf("invalid DNSKEY protocol '%d'", protocol)
	}
	algorithm, err := strconv.ParseUint(dnskeyParts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY algorithm '%s': %w", dnskeyParts[2], err)
	}
	rawPublicKey, err := base64.StdEncoding.DecodeString(dnskeyParts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY public key '%s': %w", dnskeyParts[3], err)
	}

	var publicKey crypto.PublicKey
	switch uint8(algorithm) {
	case algorithmRSASHA1, algorithmRSASHA1NSEC3SHA1, algorithmRSASHA256, algorithmRSASHA512:
		publicKey = publicKeyRSA(rawPublicKey)
	case algorithmECDSAP256SHA256, algorithmECDSAP384SHA384:
		publicKey = publicKeyECDSA(rawPublicKey, uint8(algorithm))
	case algorithmED25519:
		publicKey = publicKeyED25519(rawPublicKey)
	default:
		return nil, fmt.Errorf("unsupported DNSKEY algorithm '%d'", algorithm)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("invalid DNSKEY public key '%s'", key)
	}
	return publicKey, nil
}

// publicKeyRSA returns the RSA public key from a DNSKEY record.
//
// https://github.com/miekg/dns/blob/a6f978594be8a97447dd1a5eab6df481c7a8d9dc/dnssec.go#L500
func publicKeyRSA(keybuf []byte) *rsa.PublicKey {
	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return nil
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 || explen == 0 || keybuf[keyoff] == 0 {
		// Exponent larger than supported by the crypto package,
		// empty, or contains prohibited leading zero.
		return nil
	}

	modoff := keyoff + int(explen)
	modlen := len(keybuf) - modoff
	if modlen < 64 || modlen > 512 || keybuf[modoff] == 0 {
		// Modulus is too small, large, or contains prohibited leading zero.
		return nil
	}

	pubkey := new(rsa.PublicKey)

	var expo uint64
	// The exponent of length explen is between keyoff and modoff.
	for _, v := range keybuf[keyoff:modoff] {
		expo <<= 8
		expo |= uint64(v)
	}
	if expo > 1<<31-1 {
		// Larger exponent than supported by the crypto package.
		return nil
	}

	pubkey.E = int(expo)
	pubkey.N = new(big.Int).SetBytes(keybuf[modoff:])
	return pubkey
}

// publicKeyECDSA returns the Curve public key from the DNSKEY record.
//
// https://github.com/miekg/dns/blob/a6f978594be8a97447dd1a5eab6df481c7a8d9dc/dnssec.go#L553
func publicKeyECDSA(keybuf []byte, algorithm uint8) *ecdsa.PublicKey {
	pubkey := new(ecdsa.PublicKey)
	switch algorithm {
	case algorithmECDSAP256SHA256:
		pubkey.Curve = elliptic.P256()
		if len(keybuf) != 64 {
			// wrongly encoded key
			return nil
		}
	case algorithmECDSAP384SHA384:
		pubkey.Curve = elliptic.P384()
		if len(keybuf) != 96 {
			// Wrongly encoded key
			return nil
		}
	}
	pubkey.X = new(big.Int).SetBytes(keybuf[:len(keybuf)/2])
	pubkey.Y = new(big.Int).SetBytes(keybuf[len(keybuf)/2:])
	return pubkey
}

// publicKeyED25519 returns the Edwards-curve public key from the DNSKEY record.
//
// https://github.com/miekg/dns/blob/a6f978594be8a97447dd1a5eab6df481c7a8d9dc/dnssec.go#L578
func publicKeyED25519(keybuf []byte) ed25519.PublicKey {
	if len(keybuf) != ed25519.PublicKeySize {
		return nil
	}
	return keybuf
}

// BuildDNSKEY builds a DNSKEY record from a public key.
//
// https://github.com/miekg/dns/blob/a614451ab32ba899e34dd1e39c3978033ac94386/dnssec_keygen.go#L80-L139
func BuildDNSKEY(publicKey crypto.PublicKey) (string, error) {
	var dnskey string
	switch p := publicKey.(type) {
	case *rsa.PublicKey:
		if p.E == 0 || p.N == nil {
			return "", fmt.Errorf("invalid RSA public key")
		}
		buf := exponentToBuf(p.E)
		buf = append(buf, p.N.Bytes()...)
		dnskey = fmt.Sprintf("256 3 %d %s", algorithmRSASHA512, base64.StdEncoding.EncodeToString(buf))
	case *ecdsa.PublicKey:
		if p.X == nil || p.Y == nil {
			return "", fmt.Errorf("invalid ECDSA public key")
		}
		switch p.Curve {
		case elliptic.P256():
			dnskey = fmt.Sprintf("256 3 %d %s", algorithmECDSAP256SHA256,
				base64.StdEncoding.EncodeToString(curveToBuf(p.X, p.Y, 32)))
		case elliptic.P384():
			dnskey = fmt.Sprintf("256 3 %d %s", algorithmECDSAP384SHA384,
				base64.StdEncoding.EncodeToString(curveToBuf(p.X, p.Y, 48)))
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", p.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		if len(p) != ed25519.PublicKeySize {
			return "", fmt.Errorf("invalid Ed25519 public key")
		}
		dnskey = fmt.Sprintf("256 3 %d %s", algorithmED25519, base64.StdEncoding.EncodeToString(p))
	default:
		return "", fmt.Errorf("unsupported public key type: %T", publicKey)
	}
	return dnskey, nil
}

// Set the public key (the values E and N) for RSA RFC 3110: Section 2. RSA
// Public KEY Resource Records
func exponentToBuf(_E int) []byte {
	var buf []byte
	i := big.NewInt(int64(_E)).Bytes()
	if len(i) < 256 {
		buf = make([]byte, 1, 1+len(i))
		buf[0] = uint8(len(i))
	} else {
		buf = make([]byte, 3, 3+len(i))
		buf[0] = 0
		buf[1] = uint8(len(i) >> 8)
		buf[2] = uint8(len(i))
	}
	buf = append(buf, i...)
	return buf
}

// Set the public key for X and Y for Curve. The two values are just
// concatenated.
func curveToBuf(_X, _Y *big.Int, intlen int) []byte {
	buf := intToBytes(_X, intlen)
	buf = append(buf, intToBytes(_Y, intlen)...)
	return buf
}

// Helper function for packing and unpacking
func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}
