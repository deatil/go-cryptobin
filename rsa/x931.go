package rsa

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
)

type IX931Hasher interface {
	HashID() int
	HashSize() int
	HashMsg(msg []byte) ([]byte, error)
}

type X931Hasher struct {
	HashId int
	Hash   func() hash.Hash
}

func (h X931Hasher) HashID() int {
	return h.HashId
}

func (h X931Hasher) HashSize() int {
	d := h.Hash()
	return d.Size()
}

func (h X931Hasher) HashMsg(msg []byte) ([]byte, error) {
	d := h.Hash()
	_, err := d.Write(msg)
	if err != nil {
		return nil, err
	}

	return d.Sum(nil), nil
}

var X931HasherSha1 = X931Hasher{
	HashId: 0x33,
	Hash:   sha1.New,
}
var X931HasherSha256 = X931Hasher{
	HashId: 0x34,
	Hash:   sha256.New,
}
var X931HasherSha384 = X931Hasher{
	HashId: 0x36,
	Hash:   sha512.New384,
}
var X931HasherSha512 = X931Hasher{
	HashId: 0x35,
	Hash:   sha512.New,
}

type X931Options struct {
	Hasher IX931Hasher
}

// HashFunc returns opts.Hash so that X931Options implements crypto.SignerOpts.
func (opts *X931Options) HashFunc() crypto.Hash {
	return crypto.Hash(0)
}

func SignX931(priv *PrivateKey, hasher IX931Hasher, hashed []byte) ([]byte, error) {
	hashID, err := x9315HashInfo(hasher, len(hashed))
	if err != nil {
		return nil, err
	}

	k := priv.Size()
	em, err := emsaX931Encode(hashed, k, hashID)
	if err != nil {
		return nil, err
	}

	return decryptWithCheck(priv, em)
}

func VerifyX931(pub *PublicKey, hasher IX931Hasher, hashed []byte, sig []byte) error {
	hashID, err := x9315HashInfo(hasher, len(hashed))
	if err != nil {
		return err
	}

	k := pub.Size()
	if k < len(hashed)+2 {
		return ErrVerification
	}

	if k != len(sig) {
		return ErrVerification
	}

	em, err := encrypt(pub, sig)
	if err != nil {
		return ErrVerification
	}

	return emsaX931Verify(hashed, em, k, hashID)
}

func emsaX931Encode(mHash []byte, emLen int, hashID int) (em []byte, err error) {
	j := emLen - len(mHash) - 3
	if j < 0 {
		return nil, ErrMessageTooLong
	}

	em = make([]byte, emLen)
	em[0] = 0x6b
	for i := 1; i < j; i++ {
		em[i] = 0xbb
	}
	em[j] = 0xba

	copy(em[emLen-len(mHash)-2:], mHash)
	em[emLen-2] = byte(hashID)
	em[emLen-1] = 0xcc

	return
}

func emsaX931Verify(mHash []byte, em []byte, emLen int, hashID int) error {
	if emLen < 2 {
		return ErrVerification
	}

	j := emLen - len(mHash) - 3

	ok := subtle.ConstantTimeByteEq(em[0], 0x6b)
	ok &= subtle.ConstantTimeByteEq(em[j], 0xba)
	ok &= subtle.ConstantTimeCompare(em[emLen-len(mHash)-2:emLen-2], mHash)
	ok &= subtle.ConstantTimeByteEq(em[emLen-2], byte(hashID))
	ok &= subtle.ConstantTimeByteEq(em[emLen-1], 0xcc)

	for i := 1; i < j; i++ {
		ok &= subtle.ConstantTimeByteEq(em[i], 0xbb)
	}

	if ok != 1 {
		return ErrVerification
	}

	return nil
}

func x9315HashInfo(hasher IX931Hasher, inLen int) (hashID int, err error) {
	hashID = hasher.HashID()
	if hashID == 0 {
		return
	}

	hashLen := hasher.HashSize()
	if inLen != hashLen {
		err = errors.New("go-cryptobin/rsa: input must be hashed message")
		return
	}

	return
}
