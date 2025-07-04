package sdsa

import (
    "io"
    "hash"
    "bytes"
    "errors"
    "math/big"
    "crypto"
    "crypto/subtle"
    "encoding/asn1"
)

var (
    ErrInvalidSignerOpts = errors.New("go-cryptobin/sdsa: opts must be *SignerOpts")
)

type Hasher = func() hash.Hash

// SignerOpts contains options for creating and verifying EC-GDSA signatures.
type SignerOpts struct {
    Hash Hasher
}

// HashFunc returns opts.Hash
func (opts *SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// GetHash returns func() hash.Hash
func (opts *SignerOpts) GetHash() Hasher {
    return opts.Hash
}

// Parameters represents the domain parameters for a key. These parameters can
// be shared across many keys. The bit length of Q must be a multiple of 8.
type Parameters struct {
    P, Q, G *big.Int
}

// egdsa PublicKey
type PublicKey struct {
    Parameters

    Y *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return bigIntEqual(pub.P, xx.P) &&
        bigIntEqual(pub.Q, xx.Q) &&
        bigIntEqual(pub.G, xx.G) &&
        bigIntEqual(pub.Y, xx.Y)
}

// Verify verifies signature over the given hash and signature values (r & s).
// It returns true as a boolean value if signature is verify correctly. Otherwise
// it returns false along with error message.
func (pub *PublicKey) Verify(msg, sig []byte, opts crypto.SignerOpts) (bool, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return false, ErrInvalidSignerOpts
    }

    return VerifyASN1(pub, opt.GetHash(), msg, sig)
}

// egdsa PrivateKey
type PrivateKey struct {
    PublicKey

    X *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(&xx.PublicKey) &&
        bigIntEqual(priv.X, xx.X)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Signature generates signature over the given hash. It returns signature
// value consisting of two parts "r" and "s" as byte arrays.
func (priv *PrivateKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return nil, ErrInvalidSignerOpts
    }

    return SignASN1(random, priv, opt.GetHash(), digest)
}

// ErrInvalidPublicKey results when a public key is not usable by this code.
// FIPS is quite strict about the format of DSA keys, but other code may be
// less so. Thus, when using keys which may have been generated by other code,
// this error must be handled.
var ErrInvalidPublicKey = errors.New("go-cryptobin/sdsa: invalid public key")

// ParameterSizes is an enumeration of the acceptable bit lengths of the primes
// in a set of DSA parameters. See FIPS 186-3, section 4.2.
type ParameterSizes int

const (
    L1024N160 ParameterSizes = iota
    L2048N224
    L2048N256
    L3072N256
)

// numMRTests is the number of Miller-Rabin primality tests that we perform. We
// pick the largest recommended number from table C.1 of FIPS 186-3.
const numMRTests = 64

// GenerateParameters puts a random, valid set of DSA parameters into params.
// This function can take many seconds, even on fast machines.
func GenerateParameters(params *Parameters, rand io.Reader, sizes ParameterSizes) error {
    var L, N int
    switch sizes {
        case L1024N160:
            L = 1024
            N = 160
        case L2048N224:
            L = 2048
            N = 224
        case L2048N256:
            L = 2048
            N = 256
        case L3072N256:
            L = 3072
            N = 256
        default:
            return errors.New("go-cryptobin/sdsa: invalid ParameterSizes")
    }

    qBytes := make([]byte, N/8)
    pBytes := make([]byte, L/8)

    q := new(big.Int)
    p := new(big.Int)
    rem := new(big.Int)
    one := new(big.Int)
    one.SetInt64(1)

GeneratePrimes:
    for {
        if _, err := io.ReadFull(rand, qBytes); err != nil {
            return err
        }

        qBytes[len(qBytes)-1] |= 1
        qBytes[0] |= 0x80
        q.SetBytes(qBytes)

        if !q.ProbablyPrime(numMRTests) {
            continue
        }

        for i := 0; i < 4*L; i++ {
            if _, err := io.ReadFull(rand, pBytes); err != nil {
                return err
            }

            pBytes[len(pBytes)-1] |= 1
            pBytes[0] |= 0x80

            p.SetBytes(pBytes)
            rem.Mod(p, q)
            rem.Sub(rem, one)
            p.Sub(p, rem)
            if p.BitLen() < L {
                continue
            }

            if !p.ProbablyPrime(numMRTests) {
                continue
            }

            params.P = p
            params.Q = q
            break GeneratePrimes
        }
    }

    h := new(big.Int)
    h.SetInt64(2)
    g := new(big.Int)

    pm1 := new(big.Int).Sub(p, one)
    e := new(big.Int).Div(pm1, q)

    for {
        g.Exp(h, e, p)
        if g.Cmp(one) == 0 {
            h.Add(h, one)
            continue
        }

        params.G = g
        return nil
    }
}

// GenerateKey generates a public&private key pair. The Parameters of the
// PrivateKey must already be valid (see GenerateParameters).
func GenerateKey(priv *PrivateKey, rand io.Reader) error {
    if priv.P == nil || priv.Q == nil || priv.G == nil {
        return errors.New("go-cryptobin/sdsa: parameters not set up before generating key")
    }

    x := new(big.Int)
    xBytes := make([]byte, priv.Q.BitLen()/8)

    for {
        _, err := io.ReadFull(rand, xBytes)
        if err != nil {
            return err
        }

        x.SetBytes(xBytes)
        if x.Sign() != 0 && x.Cmp(priv.Q) < 0 {
            break
        }
    }

    priv.X = x
    priv.Y = new(big.Int)
    priv.Y.Exp(priv.G, x, priv.P)
    return nil
}

// r and s data
type sdsaSignature struct {
    R, S *big.Int
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
func SignASN1(rand io.Reader, priv *PrivateKey, hashFunc Hasher, data []byte) ([]byte, error) {
    r, s, err := Sign(rand, priv, hashFunc, data)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(sdsaSignature{
        R: r,
        S: s,
    })
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, hashFunc Hasher, data []byte, sig []byte) (bool, error) {
    var sign sdsaSignature
    _, err := asn1.Unmarshal(sig, &sign)
    if err != nil {
        return false, err
    }

    return Verify(pub, hashFunc, data, sign.R, sign.S), nil
}

// Sign data returns the Bytes encoded signature.
func SignBytes(rand io.Reader, priv *PrivateKey, hashFunc Hasher, data []byte) (sig []byte, err error) {
    r, s, err := Sign(rand, priv, hashFunc, data)
    if err != nil {
        return nil, err
    }

    h := hashFunc()
    hlen := h.Size()

    qBits := byteceil(priv.Q.BitLen())

    sig = make([]byte, hlen + qBits)

    r.FillBytes(sig[:hlen])
    s.FillBytes(sig[hlen:])

    return
}

// Verify verifies the Bytes encoded signature
func VerifyBytes(pub *PublicKey, hashFunc Hasher, data, sig []byte) bool {
    h := hashFunc()
    hlen := h.Size()

    qBits := byteceil(pub.Q.BitLen())

    if len(sig) != hlen + qBits {
        return false
    }

    r := new(big.Int).SetBytes(sig[:hlen])
    s := new(big.Int).SetBytes(sig[hlen:])

    return Verify(pub, hashFunc, data, r, s)
}

// Sign hash
func Sign(rand io.Reader, priv *PrivateKey, hashFunc Hasher, data []byte) (r, s *big.Int, err error) {
    n := priv.Q.BitLen()
    if n%8 != 0 {
        err = ErrInvalidPublicKey
        return
    }
    n >>= 3

    k := new(big.Int)
    buf := make([]byte, n)

    for {
        _, err = io.ReadFull(rand, buf)
        if err != nil {
            return
        }
        k.SetBytes(buf)

        if k.Sign() > 0 && k.Cmp(priv.Q) < 0 {
            break
        }
    }

    return SignUsingK(k, priv, hashFunc, data)
}

// sign with k
func SignUsingK(k *big.Int, priv *PrivateKey, hashFunc Hasher, data []byte) (r, s *big.Int, err error) {
    if priv.Q.Sign() <= 0 ||
        priv.P.Sign() <= 0 ||
        priv.G.Sign() <= 0 ||
        priv.X.Sign() <= 0 {
        err = ErrInvalidPublicKey
        return
    }

    h := hashFunc()

    var attempts int
    for attempts = 10; attempts > 0; attempts-- {
        /* r = h(I2BS(alpha, pi) || M) */
        pi := new(big.Int).Exp(priv.G, k, priv.P)
        piBuf := pi.FillBytes(make([]byte, byteceil(priv.P.BitLen())))

        h.Write(piBuf)
        h.Write(data)
        sig := h.Sum(nil)

        r = new(big.Int).SetBytes(sig)

        rr := new(big.Int).Set(r)
        rr.Mod(rr, priv.Q)

        if rr.Sign() == 0 {
            continue
        }

        /* Compute s = (k + r x) mod q  */
        s = new(big.Int)
        s.Mod(s.Mul(priv.X, rr), priv.Q)
        s.Mod(s.Add(s, k), priv.Q)

        if s.Sign() != 0 {
            break
        }
    }

    // Only degenerate private keys will require more than a handful of
    // attempts.
    if attempts == 0 {
        return nil, nil, ErrInvalidPublicKey
    }

    return
}

// Verify hash
func Verify(pub *PublicKey, hashFunc Hasher, data []byte, r, s *big.Int) bool {
    if pub.P.Sign() == 0 {
        return false
    }

    if r.Sign() < 1 {
        return false
    }
    if s.Sign() < 1 || s.Cmp(pub.Q) >= 0 {
        return false
    }

    h := hashFunc()

    /* Take r modulo q */
    rr := new(big.Int).Set(r)
    rr.Mod(rr, pub.Q)
    /* compute -r = (q - r) mod q */
    rr.Sub(pub.Q, rr)

    /* Compute (y ** -r) mod (p) */
    u := new(big.Int).Exp(pub.Y, rr, pub.P)

    /* Compute (g ** s) mod (p) */
    pi := new(big.Int).Exp(pub.G, s, pub.P)

    pi.Mod(pi.Mul(pi, u), pub.P)

    piBuf := pi.FillBytes(make([]byte, byteceil(pub.P.BitLen())))

    h.Write(piBuf)
    h.Write(data)
    hashed := h.Sum(nil)

    hlen := h.Size()
    rPrime := r.FillBytes(make([]byte, hlen))

    return bytes.Equal(rPrime, hashed)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

func byteceil(size int) int {
    return (size + 7) / 8
}
