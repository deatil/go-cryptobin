package rsa

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/deatil/go-cryptobin/hash/sm3"
)

// These are ASN1 DER structures:
//
//	DigestInfo ::= SEQUENCE {
//	  digestAlgorithm AlgorithmIdentifier,
//	  digest OCTET STRING
//	}
//
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
	Hash    func() hash.Hash
	Size    int
}

func (h Hasher) HashPrefixe() []byte {
	return h.Prefixe
}

func (h Hasher) HashSize() int {
	return h.Size
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
	Size:    0,
}
var HasherMd5 = Hasher{
	Prefixe: []byte{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	Hash:    md5.New,
	Size:    16,
}
var HasherSha1 = Hasher{
	Prefixe: []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	Hash:    sha1.New,
	Size:    20,
}
var HasherSha224 = Hasher{
	Prefixe: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	Hash:    sha256.New224,
	Size:    28,
}
var HasherSha256 = Hasher{
	Prefixe: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	Hash:    sha256.New,
	Size:    32,
}
var HasherSha384 = Hasher{
	Prefixe: []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	Hash:    sha512.New384,
	Size:    48,
}
var HasherSha512 = Hasher{
	Prefixe: []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	Hash:    sha512.New,
	Size:    64,
}
var HasherSha512_224 = Hasher{
	Prefixe: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1C},
	Hash:    sha512.New512_224,
	Size:    28,
}
var HasherSha512_256 = Hasher{
	Prefixe: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20},
	Hash:    sha512.New512_256,
	Size:    32,
}
var HasherSha3_224 = Hasher{
	Prefixe: []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1C},
	Hash:    sha3.New224,
	Size:    28,
}
var HasherSha3_256 = Hasher{
	Prefixe: []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20},
	Hash:    sha3.New256,
	Size:    32,
}
var HasherSha3_384 = Hasher{
	Prefixe: []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30},
	Hash:    sha3.New384,
	Size:    48,
}
var HasherSha3_512 = Hasher{
	Prefixe: []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40},
	Hash:    sha3.New512,
	Size:    64,
}
var HasherRipemd160 = Hasher{
	Prefixe: []byte{0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
	Hash:    ripemd160.New,
	Size:    20,
}
var HasherSM3 = Hasher{
	Prefixe: []byte{0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78, 0x05, 0x00, 0x04, 0x20},
	Hash:    sm3.New,
	Size:    32,
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
func SignPKCS1v15(priv *PrivateKey, hasher IHasher, hashed []byte) ([]byte, error) {
	prefix, err := pkcs1v15HashInfo(hasher, len(hashed))
	if err != nil {
		return nil, err
	}

	k := priv.Size()
	em, err := emsaPKCS1v15Encode(hashed, k, prefix)
	if err != nil {
		return nil, err
	}

	return decryptWithCheck(priv, em)
}

// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error. If hash is zero then hashed is used directly. This
// isn't advisable except for interoperability.
func VerifyPKCS1v15(pub *PublicKey, hasher IHasher, hashed []byte, sig []byte) error {
	prefix, err := pkcs1v15HashInfo(hasher, len(hashed))
	if err != nil {
		return err
	}

	k := pub.Size()
	if k < len(prefix)+len(hashed)+11 {
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

	return emsaPKCS1v15Verify(hashed, em, k, prefix)
}

func emsaPKCS1v15Encode(mHash []byte, emLen int, prefix []byte) (em []byte, err error) {
	hashLen := len(mHash)

	tLen := len(prefix) + hashLen
	if emLen < tLen+11 {
		return nil, ErrMessageTooLong
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em = make([]byte, emLen)
	em[1] = 1
	for i := 2; i < emLen-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[emLen-tLen:emLen-hashLen], prefix)
	copy(em[emLen-hashLen:emLen], mHash)

	return
}

func emsaPKCS1v15Verify(mHash []byte, em []byte, emLen int, prefix []byte) error {
	hashLen := len(mHash)
	tLen := len(prefix) + hashLen
	if emLen < tLen+11 {
		return ErrVerification
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T

	ok := subtle.ConstantTimeByteEq(em[0], 0)
	ok &= subtle.ConstantTimeByteEq(em[1], 1)
	ok &= subtle.ConstantTimeCompare(em[emLen-hashLen:emLen], mHash)
	ok &= subtle.ConstantTimeCompare(em[emLen-tLen:emLen-hashLen], prefix)
	ok &= subtle.ConstantTimeByteEq(em[emLen-tLen-1], 0)

	for i := 2; i < emLen-tLen-1; i++ {
		ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
	}

	if ok != 1 {
		return ErrVerification
	}

	return nil
}

func pkcs1v15HashInfo(hasher IHasher, inLen int) (prefix []byte, err error) {
	prefix = hasher.HashPrefixe()
	if len(prefix) == 0 {
		return
	}

	hashLen := hasher.HashSize()
	if inLen != hashLen {
		err = errors.New("go-cryptobin/rsa: input must be hashed message")
		return
	}

	return
}
