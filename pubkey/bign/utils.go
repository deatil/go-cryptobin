package bign

import (
    "errors"
    "math/big"
    "math/bits"
    "crypto/subtle"
    "encoding/binary"
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

func mathMin(a, b int) int {
    if a < b {
        return a
    }

    return b
}

// Reverse bytes
func reverse(d []byte) []byte {
    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
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

/* The additional data for bign are specific. We provide
 * helpers to extract them from an adata pointer.
 */
func GetOidFromAdata(adata []byte) (oid []byte, err error) {
    if len(adata) == 0 || len(adata) < 4 {
        return nil, errors.New("adata too short")
    }

    adatalen := uint16(len(adata))

    oidlen := uint16(adata[0]) << 8 | uint16(adata[1])
    tlen := uint16(adata[2]) << 8 | uint16(adata[3])

    if (oidlen + tlen) < tlen || (oidlen + tlen) > (adatalen - 4) {
        return nil, errors.New("adata error")
    }

    return adata[4:4+oidlen], nil
}

func GetTFromAdata(adata []byte) (t []byte, err error) {
    if len(adata) == 0 || len(adata) < 4 {
        return nil, errors.New("adata too short")
    }

    adatalen := uint16(len(adata))

    oidlen := uint16(adata[0]) << 8 | uint16(adata[1])
    tlen := uint16(adata[2]) << 8 | uint16(adata[3])

    if (oidlen + tlen) < tlen || (oidlen + tlen) > (adatalen - 4) {
        return nil, errors.New("adata error")
    }

    return adata[4+oidlen:4+oidlen+tlen], nil
}

func MakeAdata(oid, t []byte) (adata []byte) {
    adata = make([]byte, 4 + len(oid) + len(t))

    oidlen := len(oid)
    tlen := len(t)

    if oidlen > 0 {
        adata[0] = byte(oidlen >> 8)
        adata[1] = byte(oidlen & 0xff)
        copy(adata[4:], oid)
    } else{
        adata[0] = 0
        adata[1] = 0
    }

    if tlen > 0 {
        adata[2] = byte(tlen >> 8)
        adata[3] = byte(tlen & 0xff)
        copy(adata[4 + oidlen:], t)
    } else{
        adata[2] = 0
        adata[3] = 0
    }

    return adata
}
