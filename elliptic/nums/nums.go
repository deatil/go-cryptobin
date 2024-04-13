package nums

import (
    "sync"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

// see http://www.watersprings.org/pub/id/draft-black-numscurves-01.html

var (
    oidNums = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0}

    oidNumsp256d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 1}
    oidNumsp256t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 2}
    oidNumsp384d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 3}
    oidNumsp384t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 4}
    oidNumsp512d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 5}
    oidNumsp512t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 6}
)

var (
    once                   sync.Once
    p256d1, p384d1, p512d1 *elliptic.CurveParams
    p256t1, p512t1         *elliptic.CurveParams
)

func bigFromHex(s string) (i *big.Int) {
    i = new(big.Int)
    i.SetString(s, 16)
    return
}

func initAll() {
    initP256d1()
    initP384d1()
    initP512d1()

    initP256t1()
    initP512t1()
}

func initP256d1() {
    p256d1 = &elliptic.CurveParams{
        P: bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43"),
        N: bigFromHex("ffffffffffffffffffffffffffffffffe43c8275ea265c6020ab20294751a825"),
        B: bigFromHex("25581"),
        Gx: bigFromHex("01"),
        Gy: bigFromHex("696f1853c1e466d7fc82c96cceeedd6bd02c2f9375894ec10bf46306c2b56c77"),
        BitSize: 256,
        Name: "numsp256d1",
    }
}

func initP384d1() {
    p384d1 = &elliptic.CurveParams{
        P: bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3"),
        N: bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffd61eaf1eeb5d6881beda9d3d4c37e27a604d81f67b0e61b9"),
        B: bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff77bb"),
        Gx: bigFromHex("02"),
        Gy: bigFromHex("3c9f82cb4b87b4dc71e763e0663e5dbd8034ed422f04f82673330dc58d15ffa2b4a3d0bad5d30f865bcbbf503ea66f43"),
        BitSize: 384,
        Name: "numsp384d1",
    }
}

func initP512d1() {
    p512d1 = &elliptic.CurveParams{
        P: bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
        N: bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b3ca4fb94e7831b4fc258ed97d0bdc63b568b36607cd243ce153f390433555d"),
        B: bigFromHex("1d99b"),
        Gx: bigFromHex("02"),
        Gy: bigFromHex("1c282eb23327f9711952c250ea61ad53fcc13031cf6dd336e0b9328433afbdd8cc5a1c1f0c716fdc724dde537c2b0adb00bb3d08dc83755b205cc30d7f83cf28"),
        BitSize: 512,
        Name: "numsp512d1",
    }
}

// P256d1() returns a Curve which implements p256d1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P256d1() elliptic.Curve {
    once.Do(initAll)
    return p256d1
}

// P384d1() returns a Curve which implements p384d1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P384d1() elliptic.Curve {
    once.Do(initAll)
    return p384d1
}

// P512d1() returns a Curve which implements p512d1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P512d1() elliptic.Curve {
    once.Do(initAll)
    return p512d1
}

// ============

func initP256t1() {
    p256t1 = &elliptic.CurveParams{
        P: bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43"),
        N: bigFromHex("3fffffffffffffffffffffffffffffffbe6aa55ad0a6bc64e5b84e6f1122b4ad"),
        B: bigFromHex("3bee"),
        Gx: bigFromHex("0d"),
        Gy: bigFromHex("7d0ab41e2a1276dba3d330b39fa046bfbe2a6d63824d303f707f6fb5331cadba"),
        BitSize: 256,
        Name: "numsp256t1",
    }
}

func initP512t1() {
    p512t1 = &elliptic.CurveParams{
        P: bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
        N: bigFromHex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa7e50809efdabbb9a624784f449545f0dcea5ff0cb800f894e78d1cb0b5f0189"),
        B: bigFromHex("9baa8"),
        Gx: bigFromHex("20"),
        Gy: bigFromHex("7d67e841dc4c467b605091d80869212f9ceb124bf726973f9ff048779e1d614e62ae2ece5057b5dad96b7a897c1d72799261134638750f4f0cb91027543b1c5e"),
        BitSize: 512,
        Name: "numsp512t1",
    }
}

// P256t1() returns a Curve which implements p256t1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P256t1() elliptic.Curve {
    once.Do(initAll)
    return p256t1
}

// P512t1() returns a Curve which implements p512t1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P512t1() elliptic.Curve {
    once.Do(initAll)
    return p512t1
}
