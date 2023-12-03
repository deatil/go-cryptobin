package panama

import (
    "math/bits"
)

func ROTL32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

/* tau, rotate  word 'a' to the left by rol_bits bit positions */
func tau(a, rol_bits uint32) uint32 {
    return ROTL32(a, rol_bits)
}

func rotl32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr32(x, n uint32) uint32 {
    return rotl32(x, 32 - n);
}

func byteswap32(x uint32) uint32 {
    return ((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))
}
