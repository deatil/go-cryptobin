package xmss

import "math"

type Curve struct {
    n, w, h, d int
}

func NewCurve(n, w, h, d int) *Curve {
    return &Curve{
        n: n,
        w: w,
        h: h,
        d: d,
    }
}

func (c *Curve) Params() *Params {
    return NewParams(c.n, c.w, c.h, c.d)
}

// Params is a struct for parameters
type Params struct {
    n           int
    w           int
    log2w       uint
    len1        uint32
    len2        uint32
    wlen        uint32
    wotsSignLen uint32
    fullHeight  int
    d           int
    treeHeight  uint32
    indexBytes  uint32
    prvBytes    uint32
    pubBytes    uint32
    signBytes   uint32
}

func NewParams(n, w, h, d int) *Params {
    log2w := uint(math.Log2(float64(w)))
    len1 := uint32(math.Ceil(float64(8 * n / int(log2w))))
    len2 := uint32(math.Floor(math.Log2(float64(len1*uint32(w-1)))/math.Log2(float64(w)))) + 1 // len2 = 3

    wlen := len1 + len2
    wotsSignLen := wlen * uint32(n)

    treeHeight := uint32(h / d)
    indexBytes := uint32(4)

    prvBytes := indexBytes + uint32(4*n)
    pubBytes := uint32(2 * n)
    signBytes := uint32(indexBytes + uint32(n) + uint32(d)*wotsSignLen + uint32(h*n))

    return &Params{
        n:           n,
        w:           w,
        log2w:       log2w,
        len1:        len1,
        len2:        len2,
        wlen:        wlen,
        wotsSignLen: wotsSignLen,
        fullHeight:  h,
        d:           1,
        treeHeight:  treeHeight,
        indexBytes:  indexBytes,
        prvBytes:    prvBytes,
        pubBytes:    pubBytes,
        signBytes:   signBytes,
    }
}

// SignBytes the length of the signature based on a given parameter set
func (params *Params) SignBytes() int {
    return int(params.signBytes)
}

var (
    // SHA2_10_256 is parameter set using SHA-256 with n = 32, w = 16 and a Merkle Tree of height 10
    SHA2_10_256 = NewCurve(32, 16, 10, 1)
    // SHA2_16_256 is parameter set using SHA-256 with n = 32, w = 16 and a Merkle Tree of height 16
    SHA2_16_256 = NewCurve(32, 16, 16, 1)
    // SHA2_20_256 is parameter set using SHA-256 with n = 32, w = 16 and a Merkle Tree of height 20
    SHA2_20_256 = NewCurve(32, 16, 20, 1)
)
