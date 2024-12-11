package bip0340

import (
    "hash"
    "math/big"
    "math/bits"
    "crypto/sha256"
    "crypto/subtle"
    "crypto/elliptic"
    "encoding/binary"
)

const BIP0340_AUX       = "BIP0340/aux"
const BIP0340_NONCE	    = "BIP0340/nonce"
const BIP0340_CHALLENGE = "BIP0340/challenge"

var (
    zero = big.NewInt(0)
    one  = big.NewInt(1)
    two  = big.NewInt(2)
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func rotl(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func pad(x []byte, n int) []byte {
    pad := make([]byte, n - len(x))
    return append(pad, x...)
}

func bytes32(x *big.Int) []byte {
    return pad(x.Bytes(), 32)
}

func bytes64(x *big.Int) []byte {
    return pad(x.Bytes(), 64)
}

func lift_x_even_y(curve elliptic.Curve, Px, Py *big.Int) (*big.Int, *big.Int, error) {
    if new(big.Int).Mod(Py, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
        return Px, Py, nil
    } else {
        Py.Sub(curve.Params().P, Py)
        return Px, Py, nil
    }
}

func hashTag(tag string, x []byte) []byte {
    tagHash := sha256.Sum256([]byte(tag))
    toHash := tagHash[:]
    toHash = append(toHash, tagHash[:]...)
    toHash = append(toHash, x...)
    hashed := sha256.Sum256(toHash)
    return pad(hashed[:], 32)
}

func bitsToBytes(bits int) int {
    return (bits + 7) / 8
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("go-cryptobin/bip0340: internal error: invalid encoding")
    }

    return b
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

func bigintIsodd(a *big.Int) bool {
    aa := new(big.Int).Set(a)
    aa.Mod(aa, two)

    if aa.Cmp(zero) == 0 {
        return false
    }

    return true
}

func bip0340Hash(tag []byte, m []byte, h hash.Hash) {
    h.Reset()
    h.Write(tag)
    hash := h.Sum(nil)

    /* Now compute hash(hash(tag) || hash(tag) || m) */
    h.Reset()
    h.Write(hash)
    h.Write(hash)
    h.Write(m)
}

/* Set the scalar value depending on the parity bit of the input
 * point y coordinate.
 */
func bip0340SetScalar(scalar, q *big.Int, py *big.Int) {
    /* Check if Py is odd or even */
    isodd := bigintIsodd(py)

    if isodd {
        /* Replace the input scalar by (q - scalar)
         * (its opposite modulo q)
         */
        scalar.Mod(scalar.Neg(scalar), q)
    }
}
