package cipher

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type cfb64 struct {
    b       cipher.Block
    in      []byte
    out     []byte
    decrypt bool
}

func (x *cfb64) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cipher/cfb64: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cipher/cfb64: invalid buffer overlap")
    }

    for i := 0; i < len(src); i++ {
        x.b.Encrypt(x.out, x.in)

        copy(x.in, x.in[8:])

        dst[i] = src[i] ^ x.out[0]

        out := x.out[:8]
        if x.decrypt {
            out[0] = src[i]
        } else {
            out[0] = dst[i]
        }

        copy(x.in[len(x.in)-8:], out)
    }
}

func NewCFB64(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != blockSize {
        panic("cipher/cfb64: iv length must equal block size")
    }

    x := &cfb64{
        b:       block,
        in:      make([]byte, blockSize),
        out:     make([]byte, blockSize),
        decrypt: decrypt,
    }
    copy(x.in, iv)

    return x
}

func NewCFB64Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB64(block, iv, false)
}

func NewCFB64Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB64(block, iv, true)
}
