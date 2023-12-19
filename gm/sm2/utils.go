package sm2

import (
    "io"
    "math/big"
    "encoding/asn1"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

func Decompress(a []byte) *PublicKey {
    var aa, xx, xx3 sm2P256FieldElement

    P256Sm2()

    x := new(big.Int).SetBytes(a[1:])

    curve := sm2P256

    sm2P256FromBig(&xx, x)
    sm2P256Square(&xx3, &xx)       // x3 = x ^ 2
    sm2P256Mul(&xx3, &xx3, &xx)    // x3 = x ^ 2 * x
    sm2P256Mul(&aa, &curve.a, &xx) // a = a * x
    sm2P256Add(&xx3, &xx3, &aa)
    sm2P256Add(&xx3, &xx3, &curve.b)

    y2 := sm2P256ToBig(&xx3)
    y := new(big.Int).ModSqrt(y2, sm2P256.P)
    if getLastBit(y)!= uint(a[0]) {
        y.Sub(sm2P256.P, y)
    }

    return &PublicKey{
        Curve: P256Sm2(),
        X:     x,
        Y:     y,
    }
}

func Compress(a *PublicKey) []byte {
    buf := []byte{}

    yp := getLastBit(a.Y)

    buf = append(buf, a.X.Bytes()...)
    if n := len(a.X.Bytes()); n < 32 {
        buf = append(zeroByteSlice()[:(32-n)], buf...)
    }

    buf = append([]byte{byte(yp)}, buf...)

    return buf
}

func getLastBit(a *big.Int) uint {
    return 2 | a.Bit(0)
}

func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
    return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
    var sm2Sign sm2Signature

    _, err := asn1.Unmarshal(sign, &sm2Sign)
    if err != nil {
        return nil, nil, err
    }
    return sm2Sign.R, sm2Sign.S, nil
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
    var c []byte

    ct := 1
    h := sm3.New()

    for i, j := 0, (length+31)/32; i < j; i++ {
        h.Reset()
        for _, xx := range x {
            h.Write(xx)
        }

        h.Write(intToBytes(ct))

        hash := h.Sum(nil)
        if i+1 == j && length%32 != 0 {
            c = append(c, hash[:length%32]...)
        } else {
            c = append(c, hash...)
        }

        ct++
    }

    for i := 0; i < length; i++ {
        if c[i] != 0 {
            return c, true
        }
    }

    return c, false
}

func intToBytes(x int) []byte {
    var buf = make([]byte, 4)

    binary.BigEndian.PutUint32(buf, uint32(x))
    return buf
}

// 32byte
func zeroByteSlice() []byte {
    return []byte{
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    }
}

type zr struct {
    io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
    for i := range dst {
        dst[i] = 0
    }
    return len(dst), nil
}

var zeroReader = &zr{}

