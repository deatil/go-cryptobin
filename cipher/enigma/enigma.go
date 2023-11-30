package enigma

import (
    "unsafe"
    "strconv"
    "crypto/cipher"
)

const ROTORSZ int32 = 256;
const MASK uint32 = 0377;

const BlockSize = 1

type enigmaCipher struct {
    key []byte

    t1 [ROTORSZ]int8
    t2 [ROTORSZ]int8
    t3 [ROTORSZ]int8
    deck [ROTORSZ]int8
    cbuf [13]int8
    n1, n2, nr1, nr2 int32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 13:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(enigmaCipher)
    c.key = key

    c.reset()

    return c, nil
}

func (this *enigmaCipher) BlockSize() int {
    return BlockSize
}

func (this *enigmaCipher) Encrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("crypto/enigma: output not full block")
    }

    bs := len(src)

    if inexactOverlap(dst[:bs], src[:bs]) {
        panic("crypto/enigma: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *enigmaCipher) Decrypt(dst, src []byte) {
    if len(dst) < len(src) {
        panic("crypto/enigma: output not full block")
    }

    bs := len(src)

    if inexactOverlap(dst[:bs], src[:bs]) {
        panic("crypto/enigma: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *enigmaCipher) encrypt(dst, src []byte) {
    var i, j int32
    var secureflg int32 = 0

    var ciphertext []byte = make([]byte, len(src))

    copy(ciphertext, src)

    var kk int32

    var textlen int32 = int32(len(ciphertext))

    for j = 0; j < textlen; j++ {
        i = int32(ciphertext[j])

        if secureflg == 1 {
            this.nr1 = int32(uint32(this.deck[this.n1]) & MASK)
            this.nr2 = int32(uint32(this.deck[this.nr1]) & MASK)
        } else {
            this.nr1 = this.n1
        }

        kk = int32(this.t1[int32(uint32(i + this.nr1) & MASK)])
        kk = int32(this.t3[int32(uint32(kk + this.nr2) & MASK)])
        kk = int32(this.t2[int32(uint32(kk - this.nr2) & MASK)])

        i = kk - this.nr1

        ciphertext[j] = byte(i)

        this.n1++

        if this.n1 == ROTORSZ {
            this.n1 = 0
            this.n2++

            if this.n2 == ROTORSZ {
                this.n2 = 0;
            }

            if secureflg == 1 {
                this.shuffle()
            } else {
                this.nr2 = this.n2
            }
        }
    }

    copy(dst, ciphertext)
}

func (this *enigmaCipher) decrypt(dst, src []byte) {
    var i, j int32
    var secureflg int32 = 0

    var plaintext []byte = make([]byte, len(src))

    copy(plaintext, src)

    var kk int32

    var textlen int32 = int32(len(plaintext))

    for j = 0; j < textlen; j++ {
        i = int32(plaintext[j])

        if secureflg == 1 {
            this.nr1 = int32(uint32(this.deck[this.n1]) & MASK)
            this.nr2 = int32(uint32(this.deck[this.nr1]) & MASK)
        } else {
            this.nr1 = this.n1
        }

        kk = int32(this.t1[int32(uint32(i + this.nr1) & MASK)])
        kk = int32(this.t3[int32(uint32(kk + this.nr2) & MASK)])
        kk = int32(this.t2[int32(uint32(kk - this.nr2) & MASK)])

        i = kk - this.nr1

        plaintext[j] = byte(i)

        this.n1++

        if this.n1 == ROTORSZ {
            this.n1 = 0
            this.n2++

            if this.n2 == ROTORSZ {
                this.n2 = 0;
            }

            if secureflg == 1 {
                this.shuffle()
            } else {
                this.nr2 = this.n2
            }
        }
    }

    copy(dst, plaintext)
}

func (this *enigmaCipher) reset() {
    var ic, i, k, temp int32
    var random uint32
    var seed int32

    for ik, vk := range this.key {
        this.cbuf[ik] = int8(vk)
    }

    seed = 123;
    for i = 0; i < 13; i++ {
        seed = seed * int32(this.cbuf[i]) + i;
    }

    for i = 0; i < ROTORSZ; i++ {
        this.t1[i] = int8(i)
        this.deck[i] = int8(i)
    }

    for i = 0; i < ROTORSZ; i++ {
        seed = 5 * seed + int32(this.cbuf[i % 13])
        random = uint32(seed % 65521)

        k = ROTORSZ - 1 - i
        ic = int32(uint32(random) & MASK) % (k + 1)

        random >>= 8

        temp = int32(this.t1[k])
        this.t1[k] = this.t1[ic]
        this.t1[ic] = int8(temp)

        if this.t3[k] != 0 {
            continue
        }

        ic = int32(uint32(random) & MASK) % k
        for this.t3[ic] != 0 {
            ic = (ic + 1) % k
        }

        this.t3[k] = int8(ic)
        this.t3[ic] = int8(k)
    }

    for i = 0; i < ROTORSZ; i++ {
        this.t2[int32(uint32(this.t1[i]) & MASK)] = int8(i)
    }
}

func (this *enigmaCipher) shuffle() {
    var i, ic, k, temp int32
    var random uint32
    var seed int32 = 123

    for i = 0; i < ROTORSZ; i++ {
        seed = 5 * seed + int32(this.cbuf[i % 13])

        random = uint32(seed % 65521)

        k = ROTORSZ - 1 - i
        ic = int32(uint32(random) & MASK) % (k + 1)

        temp = int32(this.deck[k])
        this.deck[k] = this.deck[ic]
        this.deck[ic] = int8(temp)
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
    return "crypto/enigma: invalid key size " + strconv.Itoa(int(k))
}
