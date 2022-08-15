package crypto

import (
    "hash"
    "strconv"

    "github.com/tjfoc/gmsm/sm3"
)

type IHash interface {
    String() string
    Size() int
    New() hash.Hash
    Available() bool
}

type Hash uint

func (h Hash) HashFunc() Hash {
    return h
}

func (h Hash) String() string {
    switch h {
        case SM3:
            return "SM3"
        default:
            return "unknown hash value " + strconv.Itoa(int(h))
    }
}

const (
    SM3     Hash = 1 + iota
    maxHash
)

var digestSizes = []uint8{
    SM3: 32,
}

func (h Hash) Size() int {
    if h > 0 && h < maxHash {
        return int(digestSizes[h])
    }
    panic("crypto: Size of unknown hash function")
}

var hashes = make([]func() hash.Hash, maxHash)

func (h Hash) New() hash.Hash {
    if h > 0 && h < maxHash {
        f := hashes[h]
        if f != nil {
            return f()
        }
    }
    panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

func (h Hash) Available() bool {
    return h < maxHash && hashes[h] != nil
}

func RegisterHash(h Hash, f func() hash.Hash) {
    if h >= maxHash {
        panic("crypto: RegisterHash of unknown hash function")
    }
    hashes[h] = f
}

func init() {
    RegisterHash(SM3, sm3.New)
}
