package ecdh

import (
    "io"
    "sync"
    "errors"
    "crypto"
    "crypto/subtle"
)

type Curve interface {
    // GenerateKey generates a random PrivateKey.
    //
    // Most applications should use [crypto/rand.Reader] as rand. Note that the
    // returned key does not depend deterministically on the bytes read from rand,
    // and may change between calls and/or between versions.
    GenerateKey(rand io.Reader) (*PrivateKey, error)

    // NewPrivateKey checks that key is valid and returns a PrivateKey.
    //
    // For NIST curves, this follows SEC 1, Version 2.0, Section 2.3.6, which
    // amounts to decoding the bytes as a fixed length big endian integer and
    // checking that the result is lower than the order of the curve. The zero
    // private key is also rejected, as the encoding of the corresponding public
    // key would be irregular.
    //
    // For X25519, this only checks the scalar length.
    NewPrivateKey(key []byte) (*PrivateKey, error)

    // NewPublicKey checks that key is valid and returns a PublicKey.
    //
    // For NIST curves, this decodes an uncompressed point according to SEC 1,
    // Version 2.0, Section 2.3.4. Compressed encodings and the point at
    // infinity are rejected.
    //
    // For X25519, this only checks the u-coordinate length. Adversarially
    // selected public keys can cause ECDH to return an error.
    NewPublicKey(key []byte) (*PublicKey, error)

    // ecdh performs a ECDH exchange and returns the shared secret. It's exposed
    // as the PrivateKey.ECDH method.
    //
    // The private method also allow us to expand the ECDH interface with more
    // methods in the future without breaking backwards compatibility.
    ECDH(local *PrivateKey, remote *PublicKey) ([]byte, error)

    // PrivateKeyToPublicKey converts a PrivateKey to a PublicKey. It's exposed
    // as the PrivateKey.PublicKey method.
    //
    // This method always succeeds: for X25519, the zero key can't be
    // constructed due to clamping; for NIST curves, it is rejected by
    // NewPrivateKey.
    PrivateKeyToPublicKey(*PrivateKey) *PublicKey
}

// SM2MQV
type SM2MQVCurve interface {
    SM2MQV(sLocal, eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error)
}

// PublicKey is an ECDH public key, usually a peer's ECDH share sent over the wire.
//
// These keys can be parsed with [crypto/x509.ParsePKIXPublicKey] and encoded
// with [crypto/x509.MarshalPKIXPublicKey]. For NIST curves, they then need to
// be converted with [crypto/ecdsa.PublicKey.ECDH] after parsing.
type PublicKey struct {
    NamedCurve Curve
    KeyBytes   []byte
}

// Bytes returns a copy of the encoding of the public key.
func (k *PublicKey) Bytes() []byte {
    // Copy the public key to a fixed size buffer that can get allocated on the
    // caller's stack after inlining.
    var buf [133]byte
    return append(buf[:0], k.KeyBytes...)
}

// Equal returns whether x represents the same public key as k.
//
// Note that there can be equivalent public keys with different encodings which
// would return false from this check but behave the same way as inputs to ECDH.
//
// This check is performed in constant time as long as the key types and their
// curve match.
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return k.NamedCurve == xx.NamedCurve &&
        subtle.ConstantTimeCompare(k.KeyBytes, xx.KeyBytes) == 1
}

func (k *PublicKey) Curve() Curve {
    return k.NamedCurve
}

// PrivateKey is an ECDH private key, usually kept secret.
//
// These keys can be parsed with [crypto/x509.ParsePKCS8PrivateKey] and encoded
// with [crypto/x509.MarshalPKCS8PrivateKey]. For NIST curves, they then need to
// be converted with [crypto/ecdsa.PrivateKey.ECDH] after parsing.
type PrivateKey struct {
    NamedCurve    Curve
    KeyBytes      []byte
    // publicKey is set under publicKeyOnce, to allow loading private keys with
    // NewPrivateKey without having to perform a scalar multiplication.
    publicKey     *PublicKey
    publicKeyOnce sync.Once
}

// ECDH performs a ECDH exchange and returns the shared secret. The PrivateKey
// and PublicKey must use the same curve.
//
// For NIST curves, this performs ECDH as specified in SEC 1, Version 2.0,
// Section 3.3.1, and returns the x-coordinate encoded according to SEC 1,
// Version 2.0, Section 2.3.5. The result is never the point at infinity.
//
// For X25519, this performs ECDH as specified in RFC 7748, Section 6.1. If
// the result is the all-zero value, ECDH returns an error.
func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error) {
    if k.NamedCurve != remote.NamedCurve {
        return nil, errors.New("crypto/ecdh: private key and public key curves do not match")
    }

    return k.NamedCurve.ECDH(k, remote)
}

// SM2MQV performs a SM2 specific style ECMQV exchange and return the shared secret.
func (k *PrivateKey) SM2MQV(eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error) {
    if c, ok := k.NamedCurve.(SM2MQVCurve); ok {
        return c.SM2MQV(k, eLocal, sRemote, eRemote)
    }

    return nil, errors.New("crypto/ecdh: private key do not support MQV")
}

// Bytes returns a copy of the encoding of the private key.
func (k *PrivateKey) Bytes() []byte {
    // Copy the private key to a fixed size buffer that can get allocated on the
    // caller's stack after inlining.
    var buf [66]byte
    return append(buf[:0], k.KeyBytes...)
}

// Equal returns whether x represents the same private key as k.
//
// Note that there can be equivalent private keys with different encodings which
// would return false from this check but behave the same way as inputs to ECDH.
//
// This check is performed in constant time as long as the key types and their
// curve match.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return k.NamedCurve == xx.NamedCurve &&
        subtle.ConstantTimeCompare(k.KeyBytes, xx.KeyBytes) == 1
}

func (k *PrivateKey) Curve() Curve {
    return k.NamedCurve
}

func (k *PrivateKey) PublicKey() *PublicKey {
    k.publicKeyOnce.Do(func() {
        k.publicKey = k.NamedCurve.PrivateKeyToPublicKey(k)
    })

    return k.publicKey
}

// Public implements the implicit interface of all standard library private
// keys. See the docs of crypto.PrivateKey.
func (k *PrivateKey) Public() crypto.PublicKey {
    return k.PublicKey()
}
