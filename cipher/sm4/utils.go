package sm4

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = false

func GETU32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func PUTU32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint32(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint32(b[j:])
        }
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        if littleEndian {
            binary.LittleEndian.PutUint32(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint32(dst[j:], w[i])
        }
    }

    return dst
}

func rotl(a uint32, n uint32) uint32 {
    return bits.RotateLeft32(a, int(n))
}

func l(b uint32) uint32 {
    return b ^
           bits.RotateLeft32(b,  2) ^
           bits.RotateLeft32(b, 10) ^
           bits.RotateLeft32(b, 18) ^
           bits.RotateLeft32(b, 24)
}

func tNonLinSub(X uint32) uint32 {
    var t uint32 = 0

    t |= uint32(sbox[byte(X >> 24)]) << 24
    t |= uint32(sbox[byte(X >> 16)]) << 16
    t |= uint32(sbox[byte(X >>  8)]) <<  8
    t |= uint32(sbox[byte(X      )])

    return t
}

func tSlow(X uint32) uint32 {
    var t uint32 = tNonLinSub(X)

    /*
     * L linear transform
     */
    return t ^
           rotl(t, 2) ^
           rotl(t, 10) ^
           rotl(t, 18) ^
           rotl(t, 24)
}

func t(X uint32) uint32 {
    return sbox_t0[byte(X >> 24)] ^
           sbox_t1[byte(X >> 16)] ^
           sbox_t2[byte(X >>  8)] ^
           sbox_t3[byte(X      )]
}

func keySub(X uint32) uint32 {
    var t uint32 = tNonLinSub(X)

    return t ^ rotl(t, 13) ^ rotl(t, 23)
}
