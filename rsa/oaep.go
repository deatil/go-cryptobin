package rsa

import (
	"hash"
	"io"
)

// OAEPOptions is an interface for passing options to OAEP decryption using the
// crypto.Decrypter interface.
type OAEPOptions struct {
	// Hash is the hash function that will be used when generating the mask.
	Hash hash.Hash

	// MGFHash is the hash function used for MGF1.
	// If zero, Hash is used instead.
	MGFHash hash.Hash

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
	if opts.MGFHash != nil {
		return encryptOAEP(opts.Hash, opts.MGFHash, random, pub, msg, opts.Label)
	}

	return encryptOAEP(opts.Hash, opts.Hash, random, pub, msg, opts.Label)
}

// DecryptOAEPWithOptions decrypts ciphertext using RSA-OAEP.
func DecryptOAEPWithOptions(random io.Reader, priv *PrivateKey, ciphertext []byte, opts *OAEPOptions) ([]byte, error) {
	if opts.MGFHash != nil {
		return decryptOAEP(opts.Hash, opts.MGFHash, random, priv, ciphertext, opts.Label)
	}

	return decryptOAEP(opts.Hash, opts.Hash, random, priv, ciphertext, opts.Label)
}

func encryptOAEP(hash, mgfHash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error) {
	encrypter := NewEncrypter()
	encrypter.WithPadding(RsaOaepPadding)
	encrypter.WithRandom(random)
	encrypter.WithHash(hash)
	encrypter.WithMGFHash(mgfHash)
	encrypter.WithLabel(label)

	return encrypter.Encrypt(pub, msg)
}

func decryptOAEP(hash, mgfHash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	encrypter := NewEncrypter()
	encrypter.WithPadding(RsaOaepPadding)
	encrypter.WithRandom(random)
	encrypter.WithHash(hash)
	encrypter.WithMGFHash(mgfHash)
	encrypter.WithLabel(label)

	return encrypter.Decrypt(priv, ciphertext)
}
