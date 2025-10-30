package e521

import (
    "math/big"
    "crypto/elliptic"
)

type E521Curve struct {
    Name    string
    P       *big.Int
    N       *big.Int
    D       *big.Int
    Gx, Gy  *big.Int
    BitSize int
}

func (curve *E521Curve) Params() *elliptic.CurveParams {
    cp := new(elliptic.CurveParams)
    cp.Name = curve.Name
    cp.P = curve.P
    cp.N = curve.N
    cp.Gx = curve.Gx
    cp.Gy = curve.Gy
    cp.BitSize = curve.BitSize
    return cp
}

// polynomial returns (1 - y²) / (1 - d*y²).
func (curve *E521Curve) polynomial(y *big.Int) *big.Int {
    // Solve for x using Edwards curve equation: x² + y² = 1 + d*x²*y²
    // Rearranged to: x² = (1 - y²) / (1 - d*y²)
    y2 := new(big.Int).Mul(y, y)
    y2.Mod(y2, curve.P)

    // numerator = 1 - y²
    numerator := new(big.Int).Sub(big.NewInt(1), y2)
    numerator.Mod(numerator, curve.P)

    // denominator = 1 - d*y²
    dy2 := new(big.Int).Mul(y2, curve.D)
    dy2.Mod(dy2, curve.P)
    denominator := new(big.Int).Sub(big.NewInt(1), dy2)
    denominator.Mod(denominator, curve.P)

    // x² = numerator / denominator
    invDenom := new(big.Int).ModInverse(denominator, curve.P)
    if invDenom == nil {
        return new(big.Int)
    }

    x2 := new(big.Int).Mul(numerator, invDenom)
    x2.Mod(x2, curve.P)

    return x2
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
// check equation: x² + y² ≡ 1 + d*x²*y² (mod p),
// so we can check equation: x² = (1 - y²) / (1 - d*y²).
func (curve *E521Curve) IsOnCurve(x, y *big.Int) bool {
    if x.Sign() == 0 && y.Sign() == 0 {
        return true
    }

    x2 := new(big.Int).Mul(x, x)
    x2.Mod(x2, curve.P)

    return curve.polynomial(y).Cmp(x2) == 0
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (curve *E521Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    if x1.Sign() == 0 && y1.Sign() == 0 {
        return x2, y2
    }
    if x2.Sign() == 0 && y2.Sign() == 0 {
        return x1, y1
    }

    // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
    // y3 = (y1*y2 - x1*x2) / (1 - d*x1*x2*y1*y2)

    x1y2 := new(big.Int).Mul(x1, y2)
    y1x2 := new(big.Int).Mul(y1, x2)
    numeratorX := new(big.Int).Add(x1y2, y1x2)

    y1y2 := new(big.Int).Mul(y1, y2)
    x1x2 := new(big.Int).Mul(x1, x2)
    numeratorY := new(big.Int).Sub(y1y2, x1x2)

    dx1x2y1y2 := new(big.Int).Mul(x1x2, y1y2)
    dx1x2y1y2.Mul(dx1x2y1y2, curve.D)
    dx1x2y1y2.Mod(dx1x2y1y2, curve.P)

    denominatorX := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
    denominatorY := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)

    // Encontrar inversos modulares
    invDenomX := new(big.Int).ModInverse(denominatorX, curve.P)
    invDenomY := new(big.Int).ModInverse(denominatorY, curve.P)

    x3 := new(big.Int).Mul(numeratorX, invDenomX)
    x3.Mod(x3, curve.P)

    y3 := new(big.Int).Mul(numeratorY, invDenomY)
    y3.Mod(y3, curve.P)

    return x3, y3
}

// Double returns 2*(x,y)
func (curve *E521Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
    return curve.Add(x1, y1, x1, y1)
}

func (curve *E521Curve) ScalarMult(x, y *big.Int, k []byte) (*big.Int, *big.Int) {
    scalar := bytesToLittleInt(k)
    scalar.Mod(scalar, curve.N)

    resultX := big.NewInt(0)
    resultY := big.NewInt(1)

    tempX := new(big.Int).Set(x)
    tempY := new(big.Int).Set(y)

    for scalar.BitLen() > 0 {
        if scalar.Bit(0) == 1 {
            resultX, resultY = curve.Add(resultX, resultY, tempX, tempY)
        }

        tempX, tempY = curve.Double(tempX, tempY)
        scalar.Rsh(scalar, 1)
    }

    return resultX, resultY
}

func (curve *E521Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
    return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func (curve *E521Curve) Marshal(x, y *big.Int) []byte {
    return Marshal(curve, x, y)
}

// MarshalCompressed compresses Edwards point according to RFC 8032: store sign bit of x
func (curve *E521Curve) MarshalCompressed(x, y *big.Int) []byte {
    return MarshalCompressed(curve, x, y)
}

func (curve *E521Curve) Unmarshal(data []byte) (*big.Int, *big.Int) {
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

    x := bytesToLittleInt(data[1 : 1+byteLen])
    y := bytesToLittleInt(data[1+byteLen:])

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return x, y
}

// UnmarshalCompressed decompresses a compressed point according to RFC 8032
func (curve *E521Curve) UnmarshalCompressed(data []byte) (*big.Int, *big.Int) {
    byteLen := (curve.BitSize + 7) / 8
    if len(data) != byteLen {
        return nil, nil
    }

    // Extract sign bit from MSB of last byte
    signBit := (data[byteLen-1] >> 7) & 1

    // Clear the sign bit from y data
    yBytes := make([]byte, byteLen)
    copy(yBytes, data)
    yBytes[byteLen-1] &= 0x7F // Clear MSB

    y := bytesToLittleInt(yBytes)

    // Solve for x using Edwards curve equation: x² + y² = 1 + d*x²*y²
    x2 := curve.polynomial(y)

    // Calculate square root
    x := new(big.Int).ModSqrt(x2, curve.P)
    if x == nil {
        return nil, nil
    }

    // Choose correct x based on sign bit (RFC 8032 uses sign of x)
    xBytes := littleIntToBytes(x, byteLen)
    if (xBytes[0] & 1) != signBit {
        x.Sub(curve.P, x)
        x.Mod(x, curve.P)
    }

    return x, y
}

func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8
    ret := make([]byte, 1+2*byteLen)
    ret[0] = 4 // uncompressed point

    xBytes := littleIntToBytes(x, byteLen)
    yBytes := littleIntToBytes(y, byteLen)

    copy(ret[1:1+byteLen], xBytes)
    copy(ret[1+byteLen:], yBytes)

    return ret
}

func MarshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8
    yBytes := littleIntToBytes(y, byteLen)

    // Get the sign bit from x (LSB in little-endian representation)
    xBytes := littleIntToBytes(x, byteLen)
    signBit := xBytes[0] & 1

    // Store sign bit in the LSB of the last byte of yBytes (RFC 8032)
    compressed := make([]byte, byteLen)
    copy(compressed, yBytes)
    compressed[byteLen-1] |= signBit << 7

    return compressed
}

func Unmarshal(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*E521Curve); ok {
        return c.Unmarshal(data)
    }

    return nil, nil
}

func UnmarshalCompressed(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*E521Curve); ok {
        return c.UnmarshalCompressed(data)
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

// bytesToLittleInt converte bytes little-endian to big.Int
func bytesToLittleInt(b []byte) *big.Int {
    reversed := make([]byte, len(b))
    for i := 0; i < len(b); i++ {
        reversed[i] = b[len(b)-1-i]
    }

    return new(big.Int).SetBytes(reversed)
}

// littleIntToBytes converte big.Int to bytes little-endian
func littleIntToBytes(n *big.Int, length int) []byte {
    bytes := n.Bytes()

    if len(bytes) < length {
        padding := make([]byte, length-len(bytes))
        bytes = append(padding, bytes...)
    }

    reversed := make([]byte, length)
    for i := 0; i < length; i++ {
        reversed[i] = bytes[length-1-i]
    }

    return reversed
}
