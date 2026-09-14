package rsa

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
	"math/big"

	"github.com/deatil/go-cryptobin/tool/randutil"
)

// GenerateKey generates a random RSA private key of the given bit size.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	return GenerateMultiPrimeKey(random, 2, bits)
}

// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit
// size and the given random source.
//
// Table 1 in "[On the Security of Multi-prime RSA]" suggests maximum numbers of
// primes for a given bit size.
//
// Although the public keys are compatible (actually, indistinguishable) from
// the 2-prime case, the private keys are not. Thus it may not be possible to
// export multi-prime private keys in certain formats or to subsequently import
// them into other code.
//
// This package does not implement CRT optimizations for multi-prime RSA, so the
// keys with more than two primes will have worse performance.
//
// Deprecated: The use of this function with a number of primes different from
// two is not recommended for the above security, compatibility, and performance
// reasons. Use GenerateKey instead.
//
// [On the Security of Multi-prime RSA]: http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
func GenerateMultiPrimeKey(random io.Reader, nprimes int, bits int) (*PrivateKey, error) {
	randutil.MaybeReadByte(random)

	priv := new(PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}

	if bits < 64 {
		primeLimit := float64(uint64(1) << uint(bits/nprimes))
		// pi approximates the number of primes less than primeLimit
		pi := primeLimit / (math.Log(primeLimit) - 1)
		// Generated primes start with 11 (in binary) so we can only
		// use a quarter of them.
		pi /= 4
		// Use a factor of two to ensure that key generation terminates
		// in a reasonable amount of time.
		pi /= 2
		if pi <= float64(nprimes) {
			return nil, errors.New("crypto/rsa: too few primes of given length to generate an RSA key")
		}
	}

	primes := make([]*big.Int, nprimes)

NextSetOfPrimes:
	for {
		todo := bits
		// crypto/rand should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = rand.Prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}
			todo -= primes[i].BitLen()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime := range primes {
			for j := 0; j < i; j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}

		n := new(big.Int).Set(bigOne)
		totient := new(big.Int).Set(bigOne)
		pminus1 := new(big.Int)
		for _, prime := range primes {
			n.Mul(n, prime)
			pminus1.Sub(prime, bigOne)
			totient.Mul(totient, pminus1)
		}
		if n.BitLen() != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue NextSetOfPrimes
		}

		priv.D = new(big.Int)
		e := big.NewInt(int64(priv.E))
		ok := priv.D.ModInverse(e, totient)

		if ok != nil {
			priv.Primes = primes
			priv.N = n
			break
		}
	}

	priv.Precompute()
	return priv, nil
}
