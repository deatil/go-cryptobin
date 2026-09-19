package rsa

import (
	"crypto"
	"hash"
	"io"
)

// OAEPOptions is an interface for passing options to OAEP decryption using the
// crypto.Decrypter interface.
type OAEPOptions struct {
	// Hash is the hash function that will be used when generating the mask.
	Hash crypto.Hash

	// MGFHash is the hash function used for MGF1.
	// If zero, Hash is used instead.
	MGFHash crypto.Hash

	// Label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	Label []byte
}

// EncryptOAEP encrypts the given message with RSA-OAEP.
func EncryptOAEP(hash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error) {
	return encryptOAEP(hash, hash, random, pub, msg, label)
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
func DecryptOAEP(hash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	return decryptOAEP(hash, hash, random, priv, ciphertext, label)
}

// EncryptOAEPWithOptions encrypts the given message with RSA-OAEP.
func EncryptOAEPWithOptions(random io.Reader, pub *PublicKey, msg []byte, opts *OAEPOptions) ([]byte, error) {
	if opts.MGFHash > 0 {
		return encryptOAEP(opts.Hash.New(), opts.MGFHash.New(), random, pub, msg, opts.Label)
	}

	return encryptOAEP(opts.Hash.New(), opts.Hash.New(), random, pub, msg, opts.Label)
}

// DecryptOAEPWithOptions decrypts ciphertext using RSA-OAEP.
func DecryptOAEPWithOptions(random io.Reader, priv *PrivateKey, ciphertext []byte, opts *OAEPOptions) ([]byte, error) {
	if opts.MGFHash > 0 {
		return decryptOAEP(opts.Hash.New(), opts.MGFHash.New(), random, priv, ciphertext, opts.Label)
	}

	return decryptOAEP(opts.Hash.New(), opts.Hash.New(), random, priv, ciphertext, opts.Label)
}

func encryptOAEP(hash, mgfHash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}

	hash.Reset()
	k := pub.Size()
	if len(msg) > k-2*hash.Size()-2 {
		return nil, ErrMessageTooLong
	}

	encrypter := NewEncrypter()
	encrypter.WithPadding(RsaOaepPadding)
	encrypter.WithRandom(random)
	encrypter.WithHash(hash)
	encrypter.WithMGFHash(mgfHash)
	encrypter.WithLabel(label)

	return encrypter.Encrypt(pub, msg)
}

func decryptOAEP(hash, mgfHash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}

	k := priv.Size()
	if len(ciphertext) > k || k < hash.Size()*2+2 {
		return nil, ErrDecryption
	}

	encrypter := NewEncrypter()
	encrypter.WithPadding(RsaOaepPadding)
	encrypter.WithRandom(random)
	encrypter.WithHash(hash)
	encrypter.WithMGFHash(mgfHash)
	encrypter.WithLabel(label)

	return encrypter.Decrypt(priv, ciphertext)
}
