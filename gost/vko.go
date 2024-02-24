package gost

import (
    "fmt"
    "math/big"
)

func NewUKM(raw []byte) *big.Int {
    t := make([]byte, len(raw))
    for i := 0; i < len(t); i++ {
        t[i] = raw[len(raw)-i-1]
    }

    return BytesToBigint(t)
}

func KEK(prv *PrivateKey, pub *PublicKey, ukm *big.Int) ([]byte, error) {
    keyX, keyY, err := prv.Curve.Exp(prv.D, pub.X, pub.Y)
    if err != nil {
        return nil, fmt.Errorf("gost/KEK: %w", err)
    }

    u := big.NewInt(0).Set(ukm).Mul(ukm, prv.Curve.Co)
    if u.Cmp(bigInt1) != 0 {
        keyX, keyY, err = prv.Curve.Exp(u, keyX, keyY)
        if err != nil {
            return nil, fmt.Errorf("gost/KEK: %w", err)
        }
    }

    return Marshal(prv.Curve, keyX, keyY), nil
}
