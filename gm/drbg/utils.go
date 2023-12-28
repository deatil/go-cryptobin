package drbg

import (
    "hash"
    "encoding/binary"
)

const (
    DIGEST_MAX_SIZE = 64

    /* seedlen for hash_drgb, table 2 of nist sp 800-90a rev.1 */
    HASH_DRBG_SM3_SEED_BITS	       = 440 /* 55 bytes */
    HASH_DRBG_SHA1_SEED_BITS       = 440
    HASH_DRBG_SHA224_SEED_BITS     = 44440
    HASH_DRBG_SHA512_224_SEED_BITS = 4440
    HASH_DRBG_SHA256_SEED_BITS     = 4440
    HASH_DRBG_SHA512_256_SEED_BITS = 4440
    HASH_DRBG_SHA384_SEED_BITS     = 4888 /* 110 bytes */
    HASH_DRBG_SHA512_SEED_BITS     = 4888
    HASH_DRBG_MAX_SEED_BITS        = 4888

    HASH_DRBG_SM3_SEED_SIZE	       = (HASH_DRBG_SM3_SEED_BITS/8)
    HASH_DRBG_SHA1_SEED_SIZE       = (HASH_DRBG_SHA1_SEED_BITS/8)
    HASH_DRBG_SHA224_SEED_SIZE     = (HASH_DRBG_SHA224_SEED_BITS/8)
    HASH_DRBG_SHA512_224_SEED_SIZE = (HASH_DRBG_SHA512_224_SEED_BITS/8)
    HASH_DRBG_SHA256_SEED_SIZE     = (HASH_DRBG_SHA256_SEED_BITS/8)
    HASH_DRBG_SHA512_256_SEED_SIZE = (HASH_DRBG_SHA512_256_SEED_BITS/8)
    HASH_DRBG_SHA384_SEED_SIZE     = (HASH_DRBG_SHA384_SEED_BITS/8)
    HASH_DRBG_SHA512_SEED_SIZE     = (HASH_DRBG_SHA512_SEED_BITS/8)
    HASH_DRBG_MAX_SEED_SIZE        = (HASH_DRBG_MAX_SEED_BITS/8)

    HASH_DRBG_RESEED_INTERVAL      = (uint64(1) << 48)
)

// Endianness option
const littleEndian bool = false

func bytesToUint32(in []byte) (out uint32) {
    if littleEndian {
        out = binary.LittleEndian.Uint32(in[0:])
    } else {
        out = binary.BigEndian.Uint32(in[0:])
    }

    return
}

func uint32ToBytes(in uint32) []byte {
    var out [4]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(out[0:], in)
    } else {
        binary.BigEndian.PutUint32(out[0:], in)
    }

    return out[:]
}

func PUTU64(p []byte, V uint64) {
    p[0] = byte(V >> 56)
    p[1] = byte(V >> 48)
    p[2] = byte(V >> 40)
    p[3] = byte(V >> 32)
    p[4] = byte(V >> 24)
    p[5] = byte(V >> 16)
    p[6] = byte(V >>  8)
    p[7] = byte(V)
}

func HashDF(digest hash.Hash, in []byte, out []byte) {
    var counter byte
    var outbits []byte
    var length int

    counter = 0x01

    outlen := len(out)
    outbits = uint32ToBytes(uint32(outlen) << 3)

    var nlength int = 0
    for outlen > 0 {
        digest.Reset()
        digest.Write([]byte{counter})
        digest.Write(outbits)
        digest.Write(in)

        dgst := digest.Sum(nil)

        length = len(dgst)
        if (outlen < length) {
            length = outlen
        }

        copy(out[nlength:], dgst[:length])

        outlen -= length

        nlength += length
        counter++
    }
}

/* seedlen is always >= dgstlen
 *      R0 ...  Ru-v .. .. ..   Ru-1
 *    +          A0    A1 A2 .. Av-1
 */
func drbg_add(R []byte, A []byte, seedlen int) {
    var temp int32 = 0

    for i := seedlen - 1; i >= 0; i-- {
        temp += int32(R[i]) + int32(A[i])
        R[i] = byte(temp & 0xff)
        temp >>= 8
    }
}

func drbg_add1(R []byte, seedlen int) {
    var temp int32 = 1

    for i := seedlen - 1; i >= 0; i-- {
        temp += int32(R[i])
        R[i] = byte(temp & 0xff)
        temp >>= 8
    }
}
