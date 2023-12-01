package cast256

import (
    "unsafe"
    "strconv"
    "crypto/cipher"
)

const BlockSize = 16

type cast256Cipher struct {
    l_key [96]uint32
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

    c := new(cast256Cipher)
    c.setKey(in_key)

    return c, nil
}

func (this *cast256Cipher) BlockSize() int {
    return BlockSize
}

func (this *cast256Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("crypto/cast256: input not full block")
    }

    if len(dst) < BlockSize {
        panic("crypto/cast256: output not full block")
    }

    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("crypto/cast256: invalid buffer overlap")
    }

    blk := bytesToUint32s(src)

    blk = f_rnd(blk,  0, this.l_key)
    blk = f_rnd(blk,  8, this.l_key)
    blk = f_rnd(blk, 16, this.l_key)
    blk = f_rnd(blk, 24, this.l_key)
    blk = f_rnd(blk, 32, this.l_key)
    blk = f_rnd(blk, 40, this.l_key)

    blk = i_rnd(blk, 48, this.l_key)
    blk = i_rnd(blk, 56, this.l_key)
    blk = i_rnd(blk, 64, this.l_key)
    blk = i_rnd(blk, 72, this.l_key)
    blk = i_rnd(blk, 80, this.l_key)
    blk = i_rnd(blk, 88, this.l_key)

    dstBytes := Uint32sToBytes(blk)

    copy(dst, dstBytes[:])
}

func (this *cast256Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("crypto/cast256: input not full block")
    }

    if len(dst) < BlockSize {
        panic("crypto/cast256: output not full block")
    }

    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("crypto/cast256: invalid buffer overlap")
    }

    blk := bytesToUint32s(src)

    blk = f_rnd(blk, 88, this.l_key)
    blk = f_rnd(blk, 80, this.l_key)
    blk = f_rnd(blk, 72, this.l_key)
    blk = f_rnd(blk, 64, this.l_key)
    blk = f_rnd(blk, 56, this.l_key)
    blk = f_rnd(blk, 48, this.l_key)

    blk = i_rnd(blk, 40, this.l_key)
    blk = i_rnd(blk, 32, this.l_key)
    blk = i_rnd(blk, 24, this.l_key)
    blk = i_rnd(blk, 16, this.l_key)
    blk = i_rnd(blk,  8, this.l_key)
    blk = i_rnd(blk,  0, this.l_key)

    dstBytes := Uint32sToBytes(blk)

    copy(dst, dstBytes[:])
}

func (this *cast256Cipher) setKey(key []uint32) {
    var i, j, cm, cr uint32
    var lk, tm, tr [8]uint32

    for i = 0; i < uint32(len(key)); i++ {
        lk[i] = key[i]
    }

    cm = 0x5a827999;
    cr = 19;

    for i = 0; i < 96; i += 8 {
        for j = 0; j < 8; j++ {
            tm[j] = cm
            cm += 0x6ed9eba1
            tr[j] = cr
            cr += 17
        }

        lk = k_rnd(lk, tr, tm)

        for j = 0; j < 8; j++ {
            tm[j] = cm
            cm += 0x6ed9eba1
            tr[j] = cr
            cr += 17
        }

        lk = k_rnd(lk, tr, tm)

        this.l_key[i + 0] = lk[0]
        this.l_key[i + 1] = lk[2]
        this.l_key[i + 2] = lk[4]
        this.l_key[i + 3] = lk[6]
        this.l_key[i + 4] = lk[7]
        this.l_key[i + 5] = lk[5]
        this.l_key[i + 6] = lk[3]
        this.l_key[i + 7] = lk[1]
    }
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
    return "crypto/cast256: invalid key size " + strconv.Itoa(int(k))
}
