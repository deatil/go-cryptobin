package rsa

import (
	"io"

	"github.com/deatil/go-cryptobin/tool/randutil"
)

type RsaPadding uint

const (
    RsaPkcs1Padding RsaPadding = 1 + iota
    RsaX931Padding
    RsaNoPadding
)

type EncrypterOptions struct {
	Padding RsaPadding
}

func EncryptWithOptions(random io.Reader, pub *PublicKey, msg []byte, opts EncrypterOptions) ([]byte, error) {
	randutil.MaybeReadByte(random)

	if err := checkPub(pub); err != nil {
		return nil, err
	}

	k := pub.Size()

	var em []byte
	var err error

	switch opts.Padding {
	case RsaPkcs1Padding:
		em, err = rsaPkcs1Type2Pad(random, k, msg)
	case RsaX931Padding:
		em, err = rsaX931Pad(k, msg)
	case RsaNoPadding:
		em, err = rsaNoPad(k, msg)
	}

	if err != nil {
		return nil, err
	}

	return encrypt(pub, em)
}

func DecryptWithOptions(random io.Reader, priv *PrivateKey, ciphertext []byte, opts EncrypterOptions) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	k := priv.Size()

	em, err := decryptWithoutCheck(priv, ciphertext)
	if err != nil {
		return nil, err
	}

	var m []byte

	switch opts.Padding {
	case RsaPkcs1Padding:
		m, err = rsaPkcs1Type2Unpad(k, em)
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

func EncryptPrivateKeyWithOptions(priv *PrivateKey, msg []byte, opts EncrypterOptions) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	k := priv.Size()

	var em []byte
	var err error

	switch opts.Padding {
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

	return encryptPrivateKey(priv, em)
}

func DecryptPublicKeyWithOptions(pub *PublicKey, ciphertext []byte, opts EncrypterOptions) ([]byte, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}

	k := pub.Size()

	em, err := decryptPublicKey(pub, ciphertext)
	if err != nil {
		return nil, err
	}

	var m []byte

	switch opts.Padding {
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
