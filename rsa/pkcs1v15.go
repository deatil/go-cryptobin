// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
    "hash"
    "crypto"
    "crypto/subtle"
    "errors"
    "io"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"

    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/ripemd160"
    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/tool/randutil"
)

// This file implements encryption and decryption using PKCS #1 v1.5 padding.

// PKCS1v15DecryptOptions is for passing options to PKCS #1 v1.5 decryption using
// the crypto.Decrypter interface.
type PKCS1v15DecryptOptions struct {
    // SessionKeyLen is the length of the session key that is being
    // decrypted. If not zero, then a padding error during decryption will
    // cause a random plaintext of this length to be returned rather than
    // an error. These alternatives happen in constant time.
    SessionKeyLen int
}

// EncryptPKCS1v15 encrypts the given message with RSA and the padding
// scheme from PKCS #1 v1.5.  The message must be no longer than the
// length of the public modulus minus 11 bytes.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same
// ciphertext. Most applications should use [crypto/rand.Reader]
// as random. Note that the returned ciphertext does not depend
// deterministically on the bytes read from random, and may change
// between calls and/or between versions.
//
// WARNING: use of this function to encrypt plaintexts other than
// session keys is dangerous. Use RSA OAEP in new protocols.
func EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
    randutil.MaybeReadByte(random)

    if err := checkPub(pub); err != nil {
        return nil, err
    }
    k := pub.Size()
    if len(msg) > k-11 {
        return nil, ErrMessageTooLong
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    em := make([]byte, k)
    em[1] = 2
    ps, mm := em[2:len(em)-len(msg)-1], em[len(em)-len(msg):]
    err := nonZeroRandomBytes(ps, random)
    if err != nil {
        return nil, err
    }
    em[len(em)-len(msg)-1] = 0
    copy(mm, msg)

    return encrypt(pub, em)
}

// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
// The random parameter is legacy and ignored, and it can be nil.
//
// Note that whether this function returns an error or not discloses secret
// information. If an attacker can cause this function to run repeatedly and
// learn whether each instance returned an error then they can decrypt and
// forge signatures as if they had the private key. See
// DecryptPKCS1v15SessionKey for a way of solving this problem.
func DecryptPKCS1v15(random io.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error) {
    if err := checkPub(&priv.PublicKey); err != nil {
        return nil, err
    }

    valid, out, index, err := decryptPKCS1v15(priv, ciphertext)
    if err != nil {
        return nil, err
    }
    if valid == 0 {
        return nil, ErrDecryption
    }

    return out[index:], nil
}

// DecryptPKCS1v15SessionKey decrypts a session key using RSA and the padding
// scheme from PKCS #1 v1.5. The random parameter is legacy and ignored, and it
// can be nil.
//
// DecryptPKCS1v15SessionKey returns an error if the ciphertext is the wrong
// length or if the ciphertext is greater than the public modulus. Otherwise, no
// error is returned. If the padding is valid, the resulting plaintext message
// is copied into key. Otherwise, key is unchanged. These alternatives occur in
// constant time. It is intended that the user of this function generate a
// random session key beforehand and continue the protocol with the resulting
// value.
//
// Note that if the session key is too small then it may be possible for an
// attacker to brute-force it. If they can do that then they can learn whether a
// random value was used (because it'll be different for the same ciphertext)
// and thus whether the padding was correct. This also defeats the point of this
// function. Using at least a 16-byte key will protect against this attack.
//
// This method implements protections against Bleichenbacher chosen ciphertext
// attacks [0] described in RFC 3218 Section 2.3.2 [1]. While these protections
// make a Bleichenbacher attack significantly more difficult, the protections
// are only effective if the rest of the protocol which uses
// DecryptPKCS1v15SessionKey is designed with these considerations in mind. In
// particular, if any subsequent operations which use the decrypted session key
// leak any information about the key (e.g. whether it is a static or random
// key) then the mitigations are defeated. This method must be used extremely
// carefully, and typically should only be used when absolutely necessary for
// compatibility with an existing protocol (such as TLS) that is designed with
// these properties in mind.
//
//   - [0] “Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption
//     Standard PKCS #1”, Daniel Bleichenbacher, Advances in Cryptology (Crypto '98)
//   - [1] RFC 3218, Preventing the Million Message Attack on CMS,
//     https://www.rfc-editor.org/rfc/rfc3218.html
func DecryptPKCS1v15SessionKey(random io.Reader, priv *PrivateKey, ciphertext []byte, key []byte) error {
    if err := checkPub(&priv.PublicKey); err != nil {
        return err
    }
    k := priv.Size()
    if k-(len(key)+3+8) < 0 {
        return ErrDecryption
    }

    valid, em, index, err := decryptPKCS1v15(priv, ciphertext)
    if err != nil {
        return err
    }

    if len(em) != k {
        // This should be impossible because decryptPKCS1v15 always
        // returns the full slice.
        return ErrDecryption
    }

    valid &= subtle.ConstantTimeEq(int32(len(em)-index), int32(len(key)))
    subtle.ConstantTimeCopy(valid, key, em[len(em)-len(key):])
    return nil
}

// decryptPKCS1v15 decrypts ciphertext using priv. It returns one or zero in
// valid that indicates whether the plaintext was correctly structured.
// In either case, the plaintext is returned in em so that it may be read
// independently of whether it was valid in order to maintain constant memory
// access patterns. If the plaintext was valid then index contains the index of
// the original message in em, to allow constant time padding removal.
func decryptPKCS1v15(priv *PrivateKey, ciphertext []byte) (valid int, em []byte, index int, err error) {
    k := priv.Size()
    if k < 11 {
        err = ErrDecryption
        return
    }

    em, err = decrypt(priv, ciphertext, noCheck)
    if err != nil {
        return
    }

    firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
    secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   lookingForIndex: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    lookingForIndex := 1

    for i := 2; i < len(em); i++ {
        equals0 := subtle.ConstantTimeByteEq(em[i], 0)
        index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
        lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    validPS := subtle.ConstantTimeLessOrEq(2+8, index)

    valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
    index = subtle.ConstantTimeSelect(valid, index+1, 0)
    return valid, em, index, nil
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, random io.Reader) (err error) {
    _, err = io.ReadFull(random, s)
    if err != nil {
        return
    }

    for i := 0; i < len(s); i++ {
        for s[i] == 0 {
            _, err = io.ReadFull(random, s[i:i+1])
            if err != nil {
                return
            }
            // In tests, the PRNG may return all zeros so we do
            // this to break the loop.
            s[i] ^= 0x42
        }
    }

    return
}

// These are ASN1 DER structures:
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
// For performance, we don't use the generic ASN1 encoder. Rather, we
// precompute a prefix of the digest value that makes a valid ASN1 DER string
// with the correct contents.
type IHasher interface {
    HashPrefixe() []byte
    HashSize() int
    HashMsg(msg []byte) ([]byte, error)
}

type Hasher struct {
    Prefixe []byte
    Hash    func () hash.Hash
}

func (h Hasher) HashPrefixe() []byte {
    return h.Prefixe
}

func (h Hasher) HashSize() int {
    d := h.Hash()
    return d.Size()
}

func (h Hasher) HashMsg(msg []byte) ([]byte, error) {
    d := h.Hash()
    _, err := d.Write(msg)
    if err != nil {
        return nil, err
    }

    return d.Sum(nil), nil
}

var HasherNone = Hasher{
    Prefixe: []byte{},
}
var HasherMd5 = Hasher{
    Prefixe: []byte{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
    Hash: md5.New,
}
var HasherSha1 = Hasher{
    Prefixe: []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
    Hash: sha1.New,
}
var HasherSha224 = Hasher{
    Prefixe: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
    Hash: sha256.New224,
}
var HasherSha256 = Hasher{
    Prefixe: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
    Hash: sha256.New,
}
var HasherSha384 = Hasher{
    Prefixe: []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
    Hash: sha512.New384,
}
var HasherSha512 = Hasher{
    Prefixe: []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
    Hash: sha512.New,
}
var HasherSha512_224 = Hasher{
    Prefixe: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1C},
    Hash: sha512.New512_224,
}
var HasherSha512_256 = Hasher{
    Prefixe: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20},
    Hash: sha512.New512_256,
}
var HasherSha3_224 = Hasher{
    Prefixe: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1C},
    Hash: sha3.New224,
}
var HasherSha3_256 = Hasher{
    Prefixe: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20},
    Hash: sha3.New256,
}
var HasherSha3_384 = Hasher{
    Prefixe: []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30},
    Hash: sha3.New384,
}
var HasherSha3_512 = Hasher{
    Prefixe: []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40},
    Hash: sha3.New512,
}
var HasherRipemd160 = Hasher{
    Prefixe: []byte{0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
    Hash: ripemd160.New,
}
var HasherSM3 = Hasher{
    Prefixe: []byte{0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78, 0x05, 0x00, 0x04, 0x20},
    Hash: sm3.New,
}

type PKCS1v15Options struct {
    Hasher IHasher
}

// HashFunc returns opts.Hash so that PKCS1v15Options implements crypto.SignerOpts.
func (opts *PKCS1v15Options) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// SignPKCS1v15 calculates the signature of hashed using
// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.  Note that hashed must
// be the result of hashing the input message using the given hash
// function. If hash is zero, hashed is signed directly. This isn't
// advisable except for interoperability.
//
// The random parameter is legacy and ignored, and it can be nil.
//
// This function is deterministic. Thus, if the set of possible
// messages is small, an attacker may be able to build a map from
// messages to signatures and identify the signed messages. As ever,
// signatures provide authenticity, not confidentiality.
func SignPKCS1v15(random io.Reader, priv *PrivateKey, hasher IHasher, hashed []byte) ([]byte, error) {
    hashLen, prefix, err := pkcs1v15HashInfo(hasher, len(hashed))
    if err != nil {
        return nil, err
    }

    tLen := len(prefix) + hashLen
    k := priv.Size()
    if k < tLen+11 {
        return nil, ErrMessageTooLong
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    em := make([]byte, k)
    em[1] = 1
    for i := 2; i < k-tLen-1; i++ {
        em[i] = 0xff
    }
    copy(em[k-tLen:k-hashLen], prefix)
    copy(em[k-hashLen:k], hashed)

    return decrypt(priv, em, withCheck)
}

// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error. If hash is zero then hashed is used directly. This
// isn't advisable except for interoperability.
func VerifyPKCS1v15(pub *PublicKey, hasher IHasher, hashed []byte, sig []byte) error {
    hashLen, prefix, err := pkcs1v15HashInfo(hasher, len(hashed))
    if err != nil {
        return err
    }

    tLen := len(prefix) + hashLen
    k := pub.Size()
    if k < tLen+11 {
        return ErrVerification
    }

    // RFC 8017 Section 8.2.2: If the length of the signature S is not k
    // octets (where k is the length in octets of the RSA modulus n), output
    // "invalid signature" and stop.
    if k != len(sig) {
        return ErrVerification
    }

    em, err := encrypt(pub, sig)
    if err != nil {
        return ErrVerification
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T

    ok := subtle.ConstantTimeByteEq(em[0], 0)
    ok &= subtle.ConstantTimeByteEq(em[1], 1)
    ok &= subtle.ConstantTimeCompare(em[k-hashLen:k], hashed)
    ok &= subtle.ConstantTimeCompare(em[k-tLen:k-hashLen], prefix)
    ok &= subtle.ConstantTimeByteEq(em[k-tLen-1], 0)

    for i := 2; i < k-tLen-1; i++ {
        ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
    }

    if ok != 1 {
        return ErrVerification
    }

    return nil
}

func pkcs1v15HashInfo(hasher IHasher, inLen int) (hashLen int, prefix []byte, err error) {
    prefix = hasher.HashPrefixe()
    if len(prefix) == 0 {
        return inLen, nil, nil
    }

    hashLen = hasher.HashSize()
    if inLen != hashLen {
        return 0, nil, errors.New("go-cryptobin/rsa: input must be hashed message")
    }

    return
}

