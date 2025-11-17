package ed521

import (
    "math/big"
    "crypto/elliptic"
)

// E521
type Ed521Curve struct {
    Name    string
    P       *big.Int
    N       *big.Int
    D       *big.Int
    Gx, Gy  *big.Int
    BitSize int
}

func (curve *Ed521Curve) Params() *elliptic.CurveParams {
    cp := new(elliptic.CurveParams)
    cp.Name = curve.Name
    cp.P = curve.P
    cp.N = curve.N
    cp.Gx = curve.Gx
    cp.Gy = curve.Gy
    cp.BitSize = curve.BitSize
    return cp
}

// polynomial returns (y² - 1) / (dy² - 1).
func (curve *Ed521Curve) polynomial(y *big.Int) *big.Int {
    // x² + y² = 1 + dx²y²
    // dx²y² - x² = x²(dy² - 1) = y² - 1
    // x² = (y² - 1) / (dy² - 1)

    // u = y² - 1
    y2 := new(big.Int).Mul(y, y)
    y2.Mod(y2, curve.P)

    u := new(big.Int).Sub(y2, big.NewInt(1))
    u.Mod(u, curve.P)

    // v = dy² - 1
    v := new(big.Int).Mul(y2, curve.D)
    v.Sub(v, big.NewInt(1))
    v.Mod(v, curve.P)

    // x² = u / v
    invV := new(big.Int).ModInverse(v, curve.P)
    if invV == nil {
        return new(big.Int)
    }

    x2 := new(big.Int).Mul(u, invV)
    x2.Mod(x2, curve.P)

    return x2
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
// check equation: x² + y² ≡ 1 + d*x²*y² (mod p),
// so we can check equation: x² = (1 - y²) / (1 - d*y²).
func (curve *Ed521Curve) IsOnCurve(x, y *big.Int) bool {
    if x.Sign() == 0 && y.Sign() == 0 {
        return true
    }

    x2 := new(big.Int).Mul(x, x)
    x2.Mod(x2, curve.P)

    return curve.polynomial(y).Cmp(x2) == 0
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (curve *Ed521Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
    if x1.Sign() == 0 && y1.Sign() == 0 {
        return x2, y2
    }
    if x2.Sign() == 0 && y2.Sign() == 0 {
        return x1, y1
    }

    panicIfNotOnCurve(curve, x1, y1)
    panicIfNotOnCurve(curve, x2, y2)

    // C = X1*X2
    c := new(big.Int).Mul(x1, x2)
    // D = Y1*Y2
    d := new(big.Int).Mul(y1, y2)

    // E = d*C*D
    e := new(big.Int).Mul(c, curve.D)
    e.Mul(e, d)
    e.Mod(e, curve.P)

    // F = B-E
    f := new(big.Int).Sub(big.NewInt(1), e)
    // G = B+E
    g := new(big.Int).Add(big.NewInt(1), e)

    // H = (X1+Y1)*(X2+Y2)
    tmp1 := new(big.Int).Add(x1, y1)
    tmp2 := new(big.Int).Add(x2, y2)
    h := new(big.Int).Mul(tmp1, tmp2)

    // Z3 = F*G
    z := new(big.Int).Mul(f, g)
    zInv := new(big.Int).ModInverse(z, curve.P)

    // X3 = (z^-1) * A*F*(H-C-D)
    x = new(big.Int).Sub(h, c)
    x.Sub(x, d)
    x.Mul(x, f)
    x.Mul(x, zInv)
    x.Mod(x, curve.P)

    // Y3 = (z^-1) * A*G*(D-C)
    y = new(big.Int).Sub(d, c)
    y.Mul(y, g)
    y.Mul(y, zInv)
    y.Mod(y, curve.P)

    return
}

// Double returns 2*(x,y)
func (curve *Ed521Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
    // B = (X1+Y1)^2
    b := new(big.Int).Add(x1, y1)
    b.Mul(b, b)

    // C = X1^2
    c := new(big.Int).Mul(x1, x1)
    // D = Y1^2
    d := new(big.Int).Mul(y1, y1)

    // E = C+D
    e := new(big.Int).Add(c, d)

    // J = E-2*H
    j := new(big.Int).Sub(e, big.NewInt(2))

    // Z3 = E*J
    z := new(big.Int).Mul(e, j)
    zInv := new(big.Int).ModInverse(z, curve.P)

    // X3 = (z^-1) * (B-E)*J
    x := new(big.Int).Sub(b, e)
    x.Mul(x, j)
    x.Mul(x, zInv)
    x.Mod(x, curve.P)

    // Y3 = (z^-1) * E*(C-D)
    y := new(big.Int).Sub(c, d)
    y.Mul(y, e)
    y.Mul(y, zInv)
    y.Mod(y, curve.P)

    return x, y
}

func (curve *Ed521Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
    x, y := big.NewInt(0), big.NewInt(1)

    Bx2 := new(big.Int).Set(Bx)
    By2 := new(big.Int).Set(By)

    kk := new(big.Int).SetBytes(k)
    kk.Mod(kk, curve.N)

    for kk.BitLen() > 0 {
        if kk.Bit(0) == 1 {
            x, y = curve.Add(x, y, Bx2, By2)
        }

        Bx2, By2 = curve.Double(Bx2, By2)
        kk.Rsh(kk, 1)
    }

    return x, y
}

func (curve *Ed521Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
    return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func (curve *Ed521Curve) Marshal(x, y *big.Int) []byte {
    return Marshal(curve, x, y)
}

// MarshalCompressed compresses Edwards point according to RFC 8032: store sign bit of x
func (curve *Ed521Curve) MarshalCompressed(x, y *big.Int) []byte {
    return MarshalCompressed(curve, x, y)
}

func (curve *Ed521Curve) Unmarshal(data []byte) (*big.Int, *big.Int) {
    if len(data) == 0 {
        return nil, nil
    }

    byteLen := (curve.BitSize + 7) / 8
    if len(data) != 1+2*byteLen {
        return nil, nil
    }

    if data[0] != 4 {
        return nil, nil
    }

    p := curve.Params().P

    x := new(big.Int).SetBytes(data[1 : 1+byteLen])
    y := new(big.Int).SetBytes(data[1+byteLen:])

    if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
        return nil, nil
    }

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return x, y
}

// UnmarshalCompressed decompresses a compressed point according to RFC 8032
func (curve *Ed521Curve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
    byteLen := (curve.BitSize + 7) / 8
    if len(data) != 1+byteLen {
        return
    }
    if data[0] != 2 && data[0] != 3 { // compressed form
        return
    }

    p := curve.Params().P
    y = new(big.Int).SetBytes(data[1:])
    if y.Cmp(p) >= 0 {
        return
    }

    // x² = (y² - 1) / (dy² - 1)
    x = curve.polynomial(y)
    x = x.ModSqrt(x, curve.P)
    if x == nil {
        return
    }

    if byte(x.Bit(0)) != data[0]&1 {
        x.Neg(x).Mod(x, p)
    }

    return
}

func (curve *Ed521Curve) UnmarshalPoint(data []byte) (x, y *big.Int) {
    byteLen := (curve.BitSize + 7) / 8
    if len(data) != byteLen {
        return
    }

    size := len(data)
    eP := make([]byte, size)
    copy(eP, data)

    sign := eP[size-1] & 0x80
    eP[size - 1] &= 0x7F // got 0x7F = ~0x80

    eP = Reverse(eP)

    p := curve.Params().P
    y = new(big.Int).SetBytes(eP)
    if y.Cmp(p) >= 0 {
        return
    }

    // x² = (y² - 1) / (dy² - 1)
    x = curve.polynomial(y)
    x = x.ModSqrt(x, curve.P)
    if x == nil {
        return
    }

    if byte(sign) != data[0]&1 {
        x.Sub(p, x)
        x.Mod(x, p)
    }

    return
}

func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8

    ret := make([]byte, 1+2*byteLen)
    ret[0] = 4 // uncompressed

    x.FillBytes(ret[1 : 1+byteLen])
    y.FillBytes(ret[1+byteLen : 1+2*byteLen])

    return ret
}

func MarshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8

    compressed := make([]byte, 1+byteLen)
    compressed[0] = byte(x.Bit(0)) | 2

    y.FillBytes(compressed[1:])

    return compressed
}

func Unmarshal(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*Ed521Curve); ok {
        return c.Unmarshal(data)
    }

    return nil, nil
}

func UnmarshalCompressed(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*Ed521Curve); ok {
        return c.UnmarshalCompressed(data)
    }

    return nil, nil
}

func MarshalPoint(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8

    compressed := make([]byte, byteLen)
    y.FillBytes(compressed)

    compressed = Reverse(compressed)

    one := big.NewInt(1)

    xx := new(big.Int).Set(x)
    if xx.And(xx, one).Cmp(one) == 0 {
        compressed[byteLen-1] |= 0x80
    }

    return compressed
}

func UnmarshalPoint(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*Ed521Curve); ok {
        return c.UnmarshalPoint(data)
    }

    return nil, nil
}

func panicIfNotOnCurve(curve elliptic.Curve, x, y *big.Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on it,
    // although IsOnCurve is documented to return false for it. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return
    }

    if !curve.IsOnCurve(x, y) {
        panic("go-cryptobin/e521: attempted operation on invalid point")
    }
}

// Reverse bytes
func Reverse(b []byte) []byte {
    d := make([]byte, len(b))
    copy(d, b)

    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}
