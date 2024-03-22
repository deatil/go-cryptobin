package cast

import (
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func keyToUint32s(b []byte) []uint32 {
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

func bytesToUint32s(inp []byte) [4]uint32 {
    var blk [4]uint32

    if littleEndian {
        blk[0] = binary.LittleEndian.Uint32(inp[0:])
        blk[1] = binary.LittleEndian.Uint32(inp[4:])
        blk[2] = binary.LittleEndian.Uint32(inp[8:])
        blk[3] = binary.LittleEndian.Uint32(inp[12:])
    } else {
        blk[0] = binary.BigEndian.Uint32(inp[0:])
        blk[1] = binary.BigEndian.Uint32(inp[4:])
        blk[2] = binary.BigEndian.Uint32(inp[8:])
        blk[3] = binary.BigEndian.Uint32(inp[12:])
    }

    return blk
}

func uint32sToBytes(blk [4]uint32) [16]byte {
    var sav [16]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], blk[0])
        binary.LittleEndian.PutUint32(sav[4:], blk[1])
        binary.LittleEndian.PutUint32(sav[8:], blk[2])
        binary.LittleEndian.PutUint32(sav[12:], blk[3])
    } else {
        binary.BigEndian.PutUint32(sav[0:], blk[0])
        binary.BigEndian.PutUint32(sav[4:], blk[1])
        binary.BigEndian.PutUint32(sav[8:], blk[2])
        binary.BigEndian.PutUint32(sav[12:], blk[3])
    }

    return sav
}

func rotatel32(x uint32, n byte) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotater32(x uint32, n byte) uint32 {
    return rotatel32(x, 32 - n);
}

func swap_uint32(val uint32) uint32 {
    return (val & 0xff000000) >> 24 |
           (val & 0x00ff0000) >>  8 |
           (val & 0x0000ff00) <<  8 |
           (val & 0x000000ff) << 24
}

func f1(D uint32, kr byte, km uint32) uint32 {
    var I uint32 = rotatel32(km + D, kr)
    return ((S[0][byte(I >> 24)] ^ S[1][byte(I >> 16)]) - S[2][byte(I >> 8)]) + S[3][byte(I)]
}

func f2(D uint32, kr byte, km uint32) uint32 {
    var I uint32 = rotatel32(km ^ D, kr)
    return ((S[0][byte(I >> 24)] - S[1][byte(I >> 16)]) + S[2][byte(I >> 8)]) ^ S[3][byte(I)]
}

func f3(D uint32, kr byte, km uint32) uint32 {
    var I uint32 = rotatel32(km - D, kr)
    return ((S[0][byte(I >> 24)] + S[1][byte(I >> 16)]) ^ S[2][byte(I >> 8)]) - S[3][byte(I)]
}

func ks(i int, a, b, c, d, e, f, g, h *uint32, km []uint32, kr []byte) {
    (*g) ^= f1((*h), tr[i*2][0], tm[i*2][0])
    (*f) ^= f2((*g), tr[i*2][1], tm[i*2][1])
    (*e) ^= f3((*f), tr[i*2][2], tm[i*2][2])
    (*d) ^= f1((*e), tr[i*2][3], tm[i*2][3])
    (*c) ^= f2((*d), tr[i*2][4], tm[i*2][4])
    (*b) ^= f3((*c), tr[i*2][5], tm[i*2][5])
    (*a) ^= f1((*b), tr[i*2][6], tm[i*2][6])
    (*h) ^= f2((*a), tr[i*2][7], tm[i*2][7])
    (*g) ^= f1((*h), tr[i*2+1][0], tm[i*2+1][0])
    (*f) ^= f2((*g), tr[i*2+1][1], tm[i*2+1][1])
    (*e) ^= f3((*f), tr[i*2+1][2], tm[i*2+1][2])
    (*d) ^= f1((*e), tr[i*2+1][3], tm[i*2+1][3])
    (*c) ^= f2((*d), tr[i*2+1][4], tm[i*2+1][4])
    (*b) ^= f3((*c), tr[i*2+1][5], tm[i*2+1][5])
    (*a) ^= f1((*b), tr[i*2+1][6], tm[i*2+1][6])
    (*h) ^= f2((*a), tr[i*2+1][7], tm[i*2+1][7])

    kr[i*4+0] = byte((*a) & 0x1f)
    kr[i*4+1] = byte((*c) & 0x1f)
    kr[i*4+2] = byte((*e) & 0x1f)
    kr[i*4+3] = byte((*g) & 0x1f)
    km[i*4+0] = (*h)
    km[i*4+1] = (*f)
    km[i*4+2] = (*d)
    km[i*4+3] = (*b)
}

func keyInit(a, b, c, d, e, f, g, h *uint32, km []uint32, kr []byte) {
    ks(0, a, b, c, d, e, f, g, h, km, kr)
    ks(1, a, b, c, d, e, f, g, h, km, kr)
    ks(2, a, b, c, d, e, f, g, h, km, kr)
    ks(3, a, b, c, d, e, f, g, h, km, kr)
    ks(4, a, b, c, d, e, f, g, h, km, kr)
    ks(5, a, b, c, d, e, f, g, h, km, kr)
    ks(6, a, b, c, d, e, f, g, h, km, kr)
    ks(7, a, b, c, d, e, f, g, h, km, kr)
    ks(8, a, b, c, d, e, f, g, h, km, kr)
    ks(9, a, b, c, d, e, f, g, h, km, kr)
    ks(10, a, b, c, d, e, f, g, h, km, kr)
    ks(11, a, b, c, d, e, f, g, h, km, kr)
}
