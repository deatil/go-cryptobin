package cast

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/cast: invalid key size " + strconv.Itoa(int(k))
}

type castCipher struct {
    km []uint32
    kr []byte
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 20, 24, 28, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(castCipher)
    c.expandKey(key)

    return c, nil
}

func (this *castCipher) BlockSize() int {
    return BlockSize
}

func (this *castCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/cast: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/cast: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/cast: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *castCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/cast: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/cast: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/cast: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *castCipher) encrypt(dst, src []byte) {
    blk := bytesToUint32s(src)

    a := swap_uint32(blk[0])
    b := swap_uint32(blk[1])
    c := swap_uint32(blk[2])
    d := swap_uint32(blk[3])

    kr := this.kr
    km := this.km

    c ^= f1(d, kr[0], km[0])
    b ^= f2(c, kr[1], km[1])
    a ^= f3(b, kr[2], km[2])
    d ^= f1(a, kr[3], km[3])

    c ^= f1(d, kr[4], km[4])
    b ^= f2(c, kr[5], km[5])
    a ^= f3(b, kr[6], km[6])
    d ^= f1(a, kr[7], km[7])

    c ^= f1(d, kr[8], km[8])
    b ^= f2(c, kr[9], km[9])
    a ^= f3(b, kr[10], km[10])
    d ^= f1(a, kr[11], km[11])

    c ^= f1(d, kr[12], km[12])
    b ^= f2(c, kr[13], km[13])
    a ^= f3(b, kr[14], km[14])
    d ^= f1(a, kr[15], km[15])

    c ^= f1(d, kr[16], km[16])
    b ^= f2(c, kr[17], km[17])
    a ^= f3(b, kr[18], km[18])
    d ^= f1(a, kr[19], km[19])

    c ^= f1(d, kr[20], km[20])
    b ^= f2(c, kr[21], km[21])
    a ^= f3(b, kr[22], km[22])
    d ^= f1(a, kr[23], km[23])

    d ^= f1(a, kr[27], km[27])
    a ^= f3(b, kr[26], km[26])
    b ^= f2(c, kr[25], km[25])
    c ^= f1(d, kr[24], km[24])

    d ^= f1(a, kr[31], km[31])
    a ^= f3(b, kr[30], km[30])
    b ^= f2(c, kr[29], km[29])
    c ^= f1(d, kr[28], km[28])

    d ^= f1(a, kr[35], km[35])
    a ^= f3(b, kr[34], km[34])
    b ^= f2(c, kr[33], km[33])
    c ^= f1(d, kr[32], km[32])

    d ^= f1(a, kr[39], km[39])
    a ^= f3(b, kr[38], km[38])
    b ^= f2(c, kr[37], km[37])
    c ^= f1(d, kr[36], km[36])

    d ^= f1(a, kr[43], km[43])
    a ^= f3(b, kr[42], km[42])
    b ^= f2(c, kr[41], km[41])
    c ^= f1(d, kr[40], km[40])

    d ^= f1(a, kr[47], km[47])
    a ^= f3(b, kr[46], km[46])
    b ^= f2(c, kr[45], km[45])
    c ^= f1(d, kr[44], km[44])

    a = swap_uint32(a)
    b = swap_uint32(b)
    c = swap_uint32(c)
    d = swap_uint32(d)

    dstBytes := uint32sToBytes([4]uint32{a, b, c, d})

    copy(dst, dstBytes[:])
}

func (this *castCipher) decrypt(dst, src []byte) {
    blk := bytesToUint32s(src)

    a := swap_uint32(blk[0])
    b := swap_uint32(blk[1])
    c := swap_uint32(blk[2])
    d := swap_uint32(blk[3])

    kr := this.kr
    km := this.km

    c ^= f1(d, kr[44], km[44])
    b ^= f2(c, kr[45], km[45])
    a ^= f3(b, kr[46], km[46])
    d ^= f1(a, kr[47], km[47])

    c ^= f1(d, kr[40], km[40])
    b ^= f2(c, kr[41], km[41])
    a ^= f3(b, kr[42], km[42])
    d ^= f1(a, kr[43], km[43])

    c ^= f1(d, kr[36], km[36])
    b ^= f2(c, kr[37], km[37])
    a ^= f3(b, kr[38], km[38])
    d ^= f1(a, kr[39], km[39])

    c ^= f1(d, kr[32], km[32])
    b ^= f2(c, kr[33], km[33])
    a ^= f3(b, kr[34], km[34])
    d ^= f1(a, kr[35], km[35])

    c ^= f1(d, kr[28], km[28])
    b ^= f2(c, kr[29], km[29])
    a ^= f3(b, kr[30], km[30])
    d ^= f1(a, kr[31], km[31])

    c ^= f1(d, kr[24], km[24])
    b ^= f2(c, kr[25], km[25])
    a ^= f3(b, kr[26], km[26])
    d ^= f1(a, kr[27], km[27])

    d ^= f1(a, kr[23], km[23])
    a ^= f3(b, kr[22], km[22])
    b ^= f2(c, kr[21], km[21])
    c ^= f1(d, kr[20], km[20])

    d ^= f1(a, kr[19], km[19])
    a ^= f3(b, kr[18], km[18])
    b ^= f2(c, kr[17], km[17])
    c ^= f1(d, kr[16], km[16])

    d ^= f1(a, kr[15], km[15])
    a ^= f3(b, kr[14], km[14])
    b ^= f2(c, kr[13], km[13])
    c ^= f1(d, kr[12], km[12])

    d ^= f1(a, kr[11], km[11])
    a ^= f3(b, kr[10], km[10])
    b ^= f2(c, kr[9], km[9])
    c ^= f1(d, kr[8], km[8])

    d ^= f1(a, kr[7], km[7])
    a ^= f3(b, kr[6], km[6])
    b ^= f2(c, kr[5], km[5])
    c ^= f1(d, kr[4], km[4])

    d ^= f1(a, kr[3], km[3])
    a ^= f3(b, kr[2], km[2])
    b ^= f2(c, kr[1], km[1])
    c ^= f1(d, kr[0], km[0])

    a = swap_uint32(a)
    b = swap_uint32(b)
    c = swap_uint32(c)
    d = swap_uint32(d)

    dstBytes := uint32sToBytes([4]uint32{a, b, c, d})

    copy(dst, dstBytes[:])
}

func (this *castCipher) expandKey(key []byte) {
    keys := keyToUint32s(key)

    switch len(key) {
        case 32:
            this.expandKey256(keys)
        case 28:
            this.expandKey224(keys)
        case 24:
            this.expandKey192(keys)
        case 20:
            this.expandKey160(keys)
        case 16:
            this.expandKey128(keys)
    }
}

func (this *castCipher) expandKey256(key []uint32) {
    a := swap_uint32(key[0])
    b := swap_uint32(key[1])
    c := swap_uint32(key[2])
    d := swap_uint32(key[3])
    e := swap_uint32(key[4])
    f := swap_uint32(key[5])
    g := swap_uint32(key[6])
    h := swap_uint32(key[7])

    this.km = make([]uint32, 48)
    this.kr = make([]byte, 48)

    keyInit(&a, &b, &c, &d, &e, &f, &g, &h, this.km, this.kr)
}

func (this *castCipher) expandKey224(key []uint32) {
    a := swap_uint32(key[0])
    b := swap_uint32(key[1])
    c := swap_uint32(key[2])
    d := swap_uint32(key[3])
    e := swap_uint32(key[4])
    f := swap_uint32(key[5])
    g := swap_uint32(key[6])
    h := uint32(0)

    this.km = make([]uint32, 48)
    this.kr = make([]byte, 48)

    keyInit(&a, &b, &c, &d, &e, &f, &g, &h, this.km, this.kr)
}

func (this *castCipher) expandKey192(key []uint32) {
    a := swap_uint32(key[0])
    b := swap_uint32(key[1])
    c := swap_uint32(key[2])
    d := swap_uint32(key[3])
    e := swap_uint32(key[4])
    f := swap_uint32(key[5])
    g := uint32(0)
    h := uint32(0)

    this.km = make([]uint32, 48)
    this.kr = make([]byte, 48)

    keyInit(&a, &b, &c, &d, &e, &f, &g, &h, this.km, this.kr)
}

func (this *castCipher) expandKey160(key []uint32) {
    a := swap_uint32(key[0])
    b := swap_uint32(key[1])
    c := swap_uint32(key[2])
    d := swap_uint32(key[3])
    e := swap_uint32(key[4])
    f := uint32(0)
    g := uint32(0)
    h := uint32(0)

    this.km = make([]uint32, 48)
    this.kr = make([]byte, 48)

    keyInit(&a, &b, &c, &d, &e, &f, &g, &h, this.km, this.kr)
}

func (this *castCipher) expandKey128(key []uint32) {
    a := swap_uint32(key[0])
    b := swap_uint32(key[1])
    c := swap_uint32(key[2])
    d := swap_uint32(key[3])
    e := uint32(0)
    f := uint32(0)
    g := uint32(0)
    h := uint32(0)

    this.km = make([]uint32, 48)
    this.kr = make([]byte, 48)

    keyInit(&a, &b, &c, &d, &e, &f, &g, &h, this.km, this.kr)
}
