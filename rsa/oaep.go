package rsa

import (
	"crypto"
	"crypto/subtle"
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

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	_, err := io.ReadFull(random, seed)
	if err != nil {
		return nil, err
	}

	mgf1XOR(db, mgfHash, seed)
	mgf1XOR(seed, mgfHash, db)

	return encrypt(pub, em)
}

func decryptOAEP(hash, mgfHash hash.Hash, random io.Reader, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}
	k := priv.Size()
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, ErrDecryption
	}

	em, err := decrypt(priv, ciphertext, noCheck)
	if err != nil {
		return nil, err
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, mgfHash, db)
	mgf1XOR(db, mgfHash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, ErrDecryption
	}

	return rest[index+1:], nil
}
