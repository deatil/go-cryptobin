package rsa

import (
	"errors"
	"hash"
	"math/big"

	"github.com/deatil/go-cryptobin/tool/bigmod"
)

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// ErrMessageTooLong is returned when attempting to encrypt or sign a message
// which is too large for the size of the key. When using SignPSS, this can also
// be returned if the size of the salt is too large.
var ErrMessageTooLong = errors.New("crypto/rsa: message too long for RSA key size")

func encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	// Most of the CPU time for encryption and verification is spent in this
	// NewModulusFromBig call, because PublicKey doesn't have a Precomputed
	// field. If performance becomes an issue, consider placing a private
	// sync.Once on PublicKey to compute this.
	N, err := bigmod.NewModulusFromBig(pub.N)
	if err != nil {
		return nil, err
	}
	m, err := bigmod.NewNat().SetBytes(plaintext, N)
	if err != nil {
		return nil, err
	}
	e := uint(pub.E)

	return bigmod.NewNat().ExpShort(m, e, N).Bytes(N), nil
}

const withCheck = true
const noCheck = false

// decrypt performs an RSA decryption of ciphertext into out. If check is true,
// m^e is calculated and compared with ciphertext, in order to defend against
// errors in the CRT computation.
func decrypt(priv *PrivateKey, ciphertext []byte, check bool) ([]byte, error) {
	var (
		err  error
		m, c *bigmod.Nat
		N    *bigmod.Modulus
		t0   = bigmod.NewNat()
	)
	if priv.Precomputed.n == nil {
		N, err = bigmod.NewModulusFromBig(priv.N)
		if err != nil {
			return nil, ErrDecryption
		}
		c, err = bigmod.NewNat().SetBytes(ciphertext, N)
		if err != nil {
			return nil, ErrDecryption
		}
		m = bigmod.NewNat().Exp(c, priv.D.Bytes(), N)
	} else {
		N = priv.Precomputed.n
		P, Q := priv.Precomputed.p, priv.Precomputed.q
		Qinv, err := bigmod.NewNat().SetBytes(priv.Precomputed.Qinv.Bytes(), P)
		if err != nil {
			return nil, ErrDecryption
		}
		c, err = bigmod.NewNat().SetBytes(ciphertext, N)
		if err != nil {
			return nil, ErrDecryption
		}

		// m = c ^ Dp mod p
		m = bigmod.NewNat().Exp(t0.Mod(c, P), priv.Precomputed.Dp.Bytes(), P)
		// m2 = c ^ Dq mod q
		m2 := bigmod.NewNat().Exp(t0.Mod(c, Q), priv.Precomputed.Dq.Bytes(), Q)
		// m = m - m2 mod p
		m.Sub(t0.Mod(m2, P), P)
		// m = m * Qinv mod p
		m.Mul(Qinv, P)
		// m = m * q mod N
		m.ExpandFor(N).Mul(t0.Mod(Q.Nat(), N), N)
		// m = m + m2 mod N
		m.Add(m2.ExpandFor(N), N)
	}

	if check {
		c1 := bigmod.NewNat().ExpShort(m, uint(priv.E), N)
		if c1.Equal(c) != 1 {
			return nil, ErrDecryption
		}
	}

	return m.Bytes(N), nil
}

func decryptWithoutCheck(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, noCheck)
}

func decryptWithCheck(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, withCheck)
}

func encryptPrivateKey(priv *PrivateKey, plaintext []byte, padding RsaPadding) ([]byte, error) {
	var (
		err  error
		m, c *bigmod.Nat
		N    *bigmod.Modulus
		t0   = bigmod.NewNat()
	)

	if priv.Precomputed.n == nil {
		N, err = bigmod.NewModulusFromBig(priv.N)
		if err != nil {
			return nil, ErrDecryption
		}

		c, err = bigmod.NewNat().SetBytes(plaintext, N)
		if err != nil {
			return nil, ErrDecryption
		}

		m = bigmod.NewNat().Exp(c, priv.D.Bytes(), N)
	} else {
		N = priv.Precomputed.n
		P, Q := priv.Precomputed.p, priv.Precomputed.q
		Qinv, err := bigmod.NewNat().SetBytes(priv.Precomputed.Qinv.Bytes(), P)
		if err != nil {
			return nil, ErrDecryption
		}

		c, err = bigmod.NewNat().SetBytes(plaintext, N)
		if err != nil {
			return nil, ErrDecryption
		}

		// m = c ^ Dp mod p
		m = bigmod.NewNat().Exp(t0.Mod(c, P), priv.Precomputed.Dp.Bytes(), P)
		// m2 = c ^ Dq mod q
		m2 := bigmod.NewNat().Exp(t0.Mod(c, Q), priv.Precomputed.Dq.Bytes(), Q)
		// m = m - m2 mod p
		m.Sub(t0.Mod(m2, P), P)
		// m = m * Qinv mod p
		m.Mul(Qinv, P)
		// m = m * q mod N
		m.ExpandFor(N).Mul(t0.Mod(Q.Nat(), N), N)
		// m = m + m2 mod N
		m.Add(m2.ExpandFor(N), N)
	}

	if padding == RsaX931Padding {
		ret := new(big.Int).SetBytes(m.Bytes(N))

		f := new(big.Int).Sub(priv.N, ret)
		if f.Cmp(ret) < 0 {
			ret = new(big.Int).Set(f)
		}

		return ret.FillBytes(make([]byte, priv.Size())), nil
	}

	return m.Bytes(N), nil
}

func decryptPublicKey(pub *PublicKey, ciphertext []byte, padding RsaPadding) ([]byte, error) {
	N, err := bigmod.NewModulusFromBig(pub.N)
	if err != nil {
		return nil, err
	}

	c, err := bigmod.NewNat().SetBytes(ciphertext, N)
	if err != nil {
		return nil, err
	}

	e := uint(pub.E)
	m := bigmod.NewNat().ExpShort(c, e, N)

	mBytes := m.Bytes(N)

	// it is true if (m & 0xf) != 12
	mm := new(big.Int).SetBytes(mBytes)
	bigint15 := new(big.Int).SetInt64(int64(0xf))

	mLast4bit := new(big.Int).And(mm, bigint15)
	if padding == RsaX931Padding && mLast4bit.Int64() != 12 {
		mm = new(big.Int).Sub(pub.N, mm)

		return mm.FillBytes(make([]byte, pub.Size())), nil
	}

	return mBytes, nil
}
