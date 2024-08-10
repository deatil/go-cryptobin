package kbkdf

import (
    "github.com/deatil/go-cryptobin/tool/alias"
)

// TTAK.KO-12.0272, TTAK.KO-12.0333, NIST SP 800-108.
const (
    errInvalidCounterSize = "kbkdf: invalid counterSize"
)

// implements of Pseudo-Random Functions
type PRF interface {
    Sum(in []byte, K []byte, src ...[]byte) []byte
}

// counterSize: 0 <= counterSize <= 8
func CounterMode(prf PRF, key, label, context []byte, counterSize, length int) []byte {
    if counterSize < 0 || 8 < counterSize {
        panic(errInvalidCounterSize)
    }

    out, dst := alias.SliceForAppend(nil, length)

    var Lr [8]byte
    L := fillL(Lr[:], uint64(length*8))
    I := make([]byte, counterSize)

    var K []byte

    for off := 0; off < length; {
        alias.IncCtr(I)

        K = prf.Sum(K[:0], key, I, label, []byte{0}, context, L)
        copy(dst[off:], K)

        off += len(K)
    }

    return out
}

// counterSize: 0 <= counterSize <= 8
func FeedbackMode(prf PRF, key, label, context, iv []byte, counterSize, length int) []byte {
    if counterSize < 0 || 8 < counterSize {
        panic(errInvalidCounterSize)
    }

    out, dst := alias.SliceForAppend(nil, length)

    var Lr [8]byte
    L := fillL(Lr[:], uint64(length*8))
    I := make([]byte, counterSize)

    K := alias.BytesClone(iv)

    for off := 0; off < length; {
        alias.IncCtr(I)

        K = prf.Sum(K[:0], key, K, I, label, []byte{0}, context, L)
        copy(dst[off:], K)
        off += len(K)
    }

    return out
}

// counterSize: 0 <= counterSize <= 8
func PipelineMode(prf PRF, key, label, context []byte, counterSize, length int) []byte {
    if counterSize < 0 || 8 < counterSize {
        panic(errInvalidCounterSize)
    }

    out, dst := alias.SliceForAppend(nil, length)

    var Lr [8]byte
    L := fillL(Lr[:], uint64(length*8))
    I := make([]byte, counterSize)

    alias.IncCtr(I)
    A := prf.Sum(nil, key, label, []byte{0}, context, L)
    K := prf.Sum(nil, key, A, I, label, []byte{0}, context, L)
    off := copy(dst, K)

    for off < length {
        alias.IncCtr(I)

        A = prf.Sum(A[:0], key, A)
        K = prf.Sum(K[:0], key, A, I, label, []byte{0}, context, L)
        copy(dst[off:], K)

        off += len(K)
    }

    return out
}

func fillL(dst []byte, v uint64) []byte {
    switch {
        case v < 1<<8:
            dst[0] = byte(v)
            return dst[:1]

        case v < 1<<16:
            dst[0] = byte(v >> 8)
            dst[1] = byte(v)
            return dst[:2]

        case v < 1<<24:
            dst[0] = byte(v >> 16)
            dst[1] = byte(v >> 8)
            dst[2] = byte(v)
            return dst[:3]

        case v < 1<<32:
            dst[0] = byte(v >> 24)
            dst[1] = byte(v >> 16)
            dst[2] = byte(v >> 8)
            dst[3] = byte(v)
            return dst[:4]

        case v < 1<<40:
            dst[0] = byte(v >> 32)
            dst[1] = byte(v >> 24)
            dst[2] = byte(v >> 16)
            dst[3] = byte(v >> 8)
            dst[4] = byte(v)
            return dst[:5]

        case v < 1<<48:
            dst[0] = byte(v >> 40)
            dst[1] = byte(v >> 32)
            dst[2] = byte(v >> 24)
            dst[3] = byte(v >> 16)
            dst[4] = byte(v >> 8)
            dst[5] = byte(v)
            return dst[:6]

        case v < 1<<56:
            dst[0] = byte(v >> 48)
            dst[1] = byte(v >> 40)
            dst[2] = byte(v >> 32)
            dst[3] = byte(v >> 24)
            dst[4] = byte(v >> 16)
            dst[5] = byte(v >> 8)
            dst[6] = byte(v)
            return dst[:7]

        default:
            dst[0] = byte(v >> 56)
            dst[1] = byte(v >> 48)
            dst[2] = byte(v >> 40)
            dst[3] = byte(v >> 32)
            dst[4] = byte(v >> 24)
            dst[5] = byte(v >> 16)
            dst[6] = byte(v >> 8)
            dst[7] = byte(v)
            return dst[:8]
    }
}

