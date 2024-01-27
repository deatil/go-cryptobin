package curve

import (
    "sync"
    "errors"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

var (
    initonce sync.Once
    p256     *sm2Curve = &sm2Curve{}
)

type sm2Curve struct {
    params *elliptic.CurveParams
}

func initP256() {
    p256.params = &elliptic.CurveParams{
        Name:    "SM2-P-256",
        BitSize: 256,
        P:  bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
        N:  bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
        B:  bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
        Gx: bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
        Gy: bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
    }
}

func P256() elliptic.Curve {
    initonce.Do(initP256)
    return p256
}

func (curve *sm2Curve) Params() *elliptic.CurveParams {
    return curve.params
}

// polynomial returns x³ + a*x + b.
func (curve *sm2Curve) polynomial(x *big.Int) *big.Int {
    var a, b, aa, xx, xx3 field.Element

    a1 := new(big.Int).Sub(curve.params.P, big.NewInt(3))

    a.SetBytes(a1.Bytes())
    b.SetBytes(curve.params.B.Bytes())

    xx.SetBytes(x.Bytes())

    xx3.Square(&xx)    // x3 = x ^ 2
    xx3.Mul(&xx3, &xx) // x3 = x ^ 2 * x

    aa.Mul(&a, &xx)    // a = a * x

    xx3.Add(&xx3, &aa)
    xx3.Add(&xx3, &b)

    y := new(big.Int).SetBytes(xx3.Bytes())

    return y
}

// y^2 = x^3 + ax + b
func (curve *sm2Curve) IsOnCurve(x, y *big.Int) bool {
    if x.Sign() < 0 || x.Cmp(curve.params.P) >= 0 ||
        y.Sign() < 0 || y.Cmp(curve.params.P) >= 0 {
        return false
    }

    var y2 field.Element
    y2.SetBytes(y.Bytes())
    y2.Square(&y2) // y2 = y ^ 2

    yy := new(big.Int).SetBytes(y2.Bytes())

    return curve.polynomial(x).Cmp(yy) == 0
}

func (curve *sm2Curve) Add(x1, y1, x2, y2 *big.Int) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x1, y1)
    if err != nil {
        panic("cryptobin/sm2Curve: Add was called on an invalid point")
    }

    b, err := curve.pointFromAffine(x2, y2)
    if err != nil {
        panic("cryptobin/sm2Curve: Add was called on an invalid point")
    }

    var c PointJacobian
    c.Add(&a, &b)

    return curve.pointToAffine(c)
}

func (curve *sm2Curve) Double(x, y *big.Int) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x, y)
    if err != nil {
        panic("cryptobin/sm2Curve: Double was called on an invalid point")
    }

    a.Double(&a)

    return curve.pointToAffine(a)
}

func (curve *sm2Curve) ScalarMult(x, y *big.Int, scalar []byte) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x, y)
    if err != nil {
        panic("cryptobin/sm2Curve: ScalarMult was called on an invalid point")
    }

    scalar = curve.normalizeScalar(scalar)

    var b PointJacobian
    _, err = b.ScalarMult(&a, scalar)
    if err != nil {
        panic("cryptobin/sm2Curve: sm2 rejected normalized scalar")
    }

    return curve.pointToAffine(b)
}

func (curve *sm2Curve) ScalarBaseMult(scalar []byte) (xx, yy *big.Int) {
    scalar = curve.normalizeScalar(scalar)

    var a PointJacobian
    _, err := a.ScalarBaseMult(scalar)
    if err != nil {
        panic("cryptobin/sm2Curve: sm2 rejected normalized scalar")
    }

    return curve.pointToAffine(a)
}

// CombinedMult returns [s1]G + [s2]P where G is the generator.
func (curve *sm2Curve) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
    s1 = curve.normalizeScalar(s1)
    q, err := new(PointJacobian).ScalarBaseMult(s1)
    if err != nil {
        panic("cryptobin/sm2Curve: sm2 rejected normalized scalar")
    }

    p, err := curve.pointFromAffine(Px, Py)
    if err != nil {
        panic("cryptobin/sm2Curve: CombinedMult was called on an invalid point")
    }

    s2 = curve.normalizeScalar(s2)
    _, err = p.ScalarMult(&p, s2)
    if err != nil {
        panic("cryptobin/sm2Curve: sm2 rejected normalized scalar")
    }

    p.Add(&p, q)

    return curve.pointToAffine(p)
}

func (curve *sm2Curve) pointFromAffine(x, y *big.Int) (p PointJacobian, err error) {
    if x.Sign() == 0 && y.Sign() == 0 {
        return PointJacobian{}, nil
    }

    if x.Sign() < 0 || y.Sign() < 0 {
        return p, errors.New("cryptobin/sm2Curve: negative coordinate")
    }

    params := curve.Params()
    if params == nil {
        return p, errors.New("cryptobin/sm2Curve: params coordinate")
    }

    if x.BitLen() > params.BitSize || y.BitLen() > params.BitSize {
        return p, errors.New("cryptobin/sm2Curve: overflowing coordinate")
    }

    var a Point
    var b PointJacobian

    _, err = a.NewPoint(x, y)
    if err != nil {
        return p, err
    }

    b.FromAffine(&a)

    return b, nil
}

func (curve *sm2Curve) pointToAffine(p PointJacobian) (x, y *big.Int) {
    var a Point

    x, y = new(big.Int), new(big.Int)
    return a.FromJacobian(&p).ToBig(x, y)
}

// normalizeScalar brings the scalar within the byte size of the order of the
// curve, as expected by the nistec scalar multiplication functions.
func (curve *sm2Curve) normalizeScalar(scalar []byte) []byte {
    byteSize := (curve.params.N.BitLen() + 7) / 8
    if len(scalar) == byteSize {
        return scalar
    }

    s := new(big.Int).SetBytes(scalar)
    if len(scalar) > byteSize {
        s.Mod(s, curve.params.N)
    }

    out := make([]byte, byteSize)
    return s.FillBytes(out)
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("cryptobin/sm2: internal error: invalid encoding")
    }

    return b
}
