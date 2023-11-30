package wake

import (
    "unsafe"
    "strconv"
    "crypto/cipher"
)

const BlockSize = 1

type wakeCipher struct {
    key []uint32

    t [257]uint32
    r [4]uint32
    counter int32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    var in_key []uint32

    keyints := bytesToUint32s(key[:16])
    in_key = append(in_key, keyints[:]...)

    keyints = bytesToUint32s(key[16:])
    in_key = append(in_key, keyints[:]...)

    c := new(wakeCipher)
    c.setKey(in_key)

    return c, nil
}

func (this *wakeCipher) BlockSize() int {
    return BlockSize
}

func (this *wakeCipher) Encrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("crypto/wake: output not full block")
    }

    bs := len(src)

    if inexactOverlap(dst[:bs], src[:bs]) {
        panic("crypto/wake: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *wakeCipher) Decrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("crypto/wake: output not full block")
    }

    bs := len(src)

    if inexactOverlap(dst[:bs], src[:bs]) {
        panic("crypto/wake: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *wakeCipher) encrypt(dst, src []byte) {
    var r2, r3, r4, r5 uint32
    var r6 uint32
    var i int32

    input := make([]byte, len(src))
    copy(input, src)

    r3 = this.r[0]
    r4 = this.r[1]
    r5 = this.r[2]
    r6 = this.r[3]

    for i = 0; i < int32(len(input)); i++ {
        /* R1 = V[n] = V[n] XOR R6 - here we do it per byte --sloooow */
        /* R1 is ignored */
        input[i] ^= byte(r6 >> (this.counter * 4))

        /* R2 = V[n] = R1 - per byte also */
        r2 |= uint32(input[i] >> (this.counter * 4))
        this.counter++;

        if (this.counter == 4) { /* r6 was used - update it! */
            this.counter = 0

            /* these swaps are because we do operations per byte */
            r2 = byteswap32(r2)
            r6 = byteswap32(r6)

            r3 = this.M(r3, r2)
            r4 = this.M(r4, r3)
            r5 = this.M(r5, r4)
            r6 = this.M(r6, r5)

            r6 = byteswap32(r6)
        }
    }

    this.r[0] = r3
    this.r[1] = r4
    this.r[2] = r5
    this.r[3] = r6

    copy(dst, input)
}

func (this *wakeCipher) decrypt(dst, src []byte) {
    var r1, r3, r4, r5 uint32
    var r6 uint32
    var i int32

    input := make([]byte, len(src))
    copy(input, src)

    r3 = this.r[0]
    r4 = this.r[1]
    r5 = this.r[2]
    r6 = this.r[3]

    for i = 0; i < int32(len(input)); i++ {
        /* R1 = V[n] */
        r1 = uint32(input[i] >> (this.counter * 4))

        /* R2 = V[n] = V[n] ^ R6 */
        /* R2 is ignored */
        input[i] ^= byte(r6 >> (this.counter * 4))
        this.counter++;

        if (this.counter == 4) {
            this.counter = 0

            r1 = byteswap32(r1)
            r6 = byteswap32(r6)
            r3 = this.M(r3, r1)
            r4 = this.M(r4, r3)
            r5 = this.M(r5, r4)
            r6 = this.M(r6, r5)

            r6 = byteswap32(r6)
        }
    }

    this.r[0] = r3
    this.r[1] = r4
    this.r[2] = r5
    this.r[3] = r6

    copy(dst, input)
}

var tt = [10]uint32{
    0x726a8f3b,
    0xe69a3b5c,
    0xd3c71fe5,
    0xab3c73d2,
    0x4d3a8eb3,
    0x0396d6e8,
    0x3d4c2f7a,
    0x9ee27cf3,
}

func (this *wakeCipher) setKey(key []uint32) {
    var x, z, p uint32
    var k [4]uint32

    k[0] = byteswap32(key[0]);
    k[1] = byteswap32(key[1]);
    k[2] = byteswap32(key[2]);
    k[3] = byteswap32(key[3]);

    for p = 0; p < 4; p++ {
        this.t[p] = k[p]
    }

    for p = 4; p < 256; p++ {
        x = this.t[p - 4] + this.t[p - 1]
        this.t[p] = x >> 3 ^ tt[x & 7]
    }

    for p = 0; p < 23; p++ {
        this.t[p] += this.t[p + 89]
    }

    x = this.t[33]
    z = this.t[59] | 0x01000001
    z &= 0xff7fffff

    for p = 0; p < 256; p++ {
        x = (x & 0xff7fffff) + z
        this.t[p] = (this.t[p] & 0x00ffffff) ^ x
    }

    this.t[256] = this.t[0]
    x &= 0xff

    for p = 0; p < 256; p++ {
        x = (this.t[p ^ x] ^ x) & 0xff

        this.t[p] = this.t[x]
        this.t[x] = this.t[p + 1]
    }

    this.counter = 0;

    this.r[0] = k[0];
    this.r[1] = k[1];
    this.r[2] = k[2];

    this.r[3] = byteswap32(k[3]);
}

func (this *wakeCipher) M(X uint32, Y uint32) uint32 {
    var TMP uint32

    TMP = X + Y;

    return (((TMP >> 8) & 0x00ffffff) ^ this.t[TMP & 0xff])
}

// anyOverlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
func anyOverlap(x, y []byte) bool {
    return len(x) > 0 && len(y) > 0 &&
        uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
        uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// inexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// inexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func inexactOverlap(x, y []byte) bool {
    if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
        return false
    }

    return anyOverlap(x, y)
}

type KeySizeError int

func (k KeySizeError) Error() string {
    return "crypto/wake: invalid key size " + strconv.Itoa(int(k))
}
