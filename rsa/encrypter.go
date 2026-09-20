package rsa

import (
	"errors"
	"hash"
	"io"
)

type RsaPadding uint

const (
	RsaPkcs1Padding RsaPadding = 1 + iota
	RsaOaepPadding
	RsaX931Padding
	RsaNoPadding
)

type Encrypter struct {
	// rsa padding type
	padding RsaPadding

	// rsa rand
	random io.Reader

	// Hash is the hash function that will be used when generating the mask.
	hash hash.Hash

	// MGFHash is the hash function used for MGF1.
	mgfHash hash.Hash

	// Label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	label []byte
}

func NewEncrypter() *Encrypter {
	e := new(Encrypter)
	return e
}

func (e *Encrypter) WithPadding(padding RsaPadding) {
	e.padding = padding
}

func (e *Encrypter) WithRandom(random io.Reader) {
	e.random = random
}

func (e *Encrypter) WithHash(hash hash.Hash) {
	e.hash = hash
}

func (e *Encrypter) WithMGFHash(mgfHash hash.Hash) {
	e.mgfHash = mgfHash
}

func (e *Encrypter) WithLabel(label []byte) {
	e.label = label
}

func (e *Encrypter) Encrypt(pub *PublicKey, msg []byte) ([]byte, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}

	k := pub.Size()

	var em []byte
	var err error

	switch e.padding {
	case RsaPkcs1Padding:
		em, err = rsaPkcs1Type2Pad(e.random, k, msg)
	case RsaOaepPadding:
		if e.mgfHash != nil {
			em, err = rsaOaepPad(e.hash, e.mgfHash, e.random, k, msg, e.label)
		} else {
			em, err = rsaOaepPad(e.hash, e.hash, e.random, k, msg, e.label)
		}
	case RsaNoPadding:
		em, err = rsaNoPad(k, msg)
	default:
		return nil, errors.New("go-cryptobin/rsa: padding not supported")
	}

	if err != nil {
		return nil, err
	}

	return encrypt(pub, em)
}

func (e *Encrypter) Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	em, err := decryptWithoutCheck(priv, ciphertext)
	if err != nil {
		return nil, err
	}

	k := priv.Size()

	var m []byte

	switch e.padding {
	case RsaPkcs1Padding:
		m, err = rsaPkcs1Type2Unpad(k, em)
	case RsaOaepPadding:
		if e.mgfHash != nil {
			m, err = rsaOaepUnpad(e.hash, e.mgfHash, k, em, e.label)
		} else {
			m, err = rsaOaepUnpad(e.hash, e.hash, k, em, e.label)
		}
	case RsaNoPadding:
		m, err = rsaNoUnpad(k, em)
	default:
		return nil, errors.New("go-cryptobin/rsa: padding not supported")
	}

	if err != nil {
		return nil, err
	}

	return m, nil
}

func (e *Encrypter) EncryptPrivateKey(priv *PrivateKey, msg []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	k := priv.Size()

	var em []byte
	var err error

	switch e.padding {
	case RsaPkcs1Padding:
		em, err = rsaPkcs1Type1Pad(k, msg)
	case RsaX931Padding:
		em, err = rsaX931Pad(k, msg)
	case RsaNoPadding:
		em, err = rsaNoPad(k, msg)
	}

	if err != nil {
		return nil, err
	}

	return encryptPrivateKey(priv, em, e.padding)
}

func (e *Encrypter) DecryptPublicKey(pub *PublicKey, ciphertext []byte) ([]byte, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}

	em, err := decryptPublicKey(pub, ciphertext, e.padding)
	if err != nil {
		return nil, err
	}

	k := pub.Size()

	var m []byte

	switch e.padding {
	case RsaPkcs1Padding:
		m, err = rsaPkcs1Type1Unpad(k, em)
	case RsaX931Padding:
		m, err = rsaX931Unpad(k, em)
	case RsaNoPadding:
		m, err = rsaNoUnpad(k, em)
	}

	if err != nil {
		return nil, err
	}

	return m, nil
}
