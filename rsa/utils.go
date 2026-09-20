package rsa

import (
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("go-cryptobin/rsa: decryption error")

// ErrVerification represents a failure to verify a signature.
// It is deliberately vague to avoid adaptive attacks.
var ErrVerification = errors.New("go-cryptobin/rsa: verification error")

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
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
