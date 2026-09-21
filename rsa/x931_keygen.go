package rsa

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
	"math/big"
)

// GenerateX931Key generates a random RSA private key of the given bit size.
func GenerateX931Key(random io.Reader, bits int) (*PrivateKey, error) {
	return GenerateX931MultiPrimeKey(random, 2, bits)
}

// GenerateX931MultiPrimeKey generates a multi-prime RSA keypair of the given bit
// size and the given random source.
func GenerateX931MultiPrimeKey(random io.Reader, nprimes int, bits int) (*PrivateKey, error) {
	priv := new(PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("go-cryptobin/rsa: GenerateX931MultiPrimeKey: nprimes must be >= 2")
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
			return nil, errors.New("go-cryptobin/rsa: too few primes of given length to generate an RSA key")
		}
	}

	big4 := big.NewInt(int64(4))
	big3 := big.NewInt(int64(3))

	primes := make([]*big.Int, nprimes)

NextSetOfPrimes:
	for {
		todo := bits

		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}

		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = rand.Prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}

			// if prime % 4 == 3, it is true
			prem := new(big.Int).Mod(primes[i], big4)
			if prem.Cmp(big3) != 0 {
				continue NextSetOfPrimes
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
