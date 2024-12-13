package bip0340

import (
    "math/big"
    "crypto/sha256"
    "crypto/elliptic"

    "golang.org/x/crypto/chacha20"
)

/*
 * BIP0340 batch verification functions.
 */
func BatchVerify(pub []*PublicKey, m, sig [][]byte, hashFunc Hasher) bool {
    u := len(pub)

    if len(m) == 0 || len(m) < u || len(sig) < u {
        return false
    }

    a := make([]*big.Int, u)
    Px := make([]*big.Int, u)
    Py := make([]*big.Int, u)
    r := make([]*big.Int, u)
    s := make([]*big.Int, u)
    e := make([]*big.Int, u)
    Rx := make([]*big.Int, u)
    Ry := make([]*big.Int, u)

    h := hashFunc()
    pub0 := pub[0]

    curve := pub0.Curve
    curveParams := curve.Params()

    p := curveParams.P
    plen := (p.BitLen() + 7) / 8

    var seed []byte
    for i := 0; i < u; i++ {
        if pub[i].Curve != pub0.Curve {
            return false
        }

        pubx := make([]byte, plen)
        pub[i].X.FillBytes(pubx)

        seed = append(seed, pubx...)
        seed = append(seed, m[i]...)
        seed = append(seed, sig[i]...)
    }

    seedFixed := sha256.Sum256(seed)
    seed = seedFixed[:]

    a[0] = big.NewInt(1)
    for i := 1; i < u; i++ {
        bytes, _ := chacha20.HChaCha20(seed, pad([]byte{}, 16))
        a[i] = new(big.Int).SetBytes(bytes)

        if a[i].Cmp(big.NewInt(0)) <= 0 || a[i].Cmp(curveParams.N) >= 0 {
            i--
        }
    }

    for i := 0; i < u; i++ {
        var err error
        Px[i], Py[i], err = liftXEvenY(curve, pub[i].X, pub[i].Y)
        if err != nil {
            return false
        }

        /* Extract r and s */
        r[i] = new(big.Int).SetBytes(sig[i][:plen])
        if r[i].Cmp(curveParams.P) >= 0 {
            return false
        }

        s[i] = new(big.Int).SetBytes(sig[i][plen:])
        if s[i].Cmp(curveParams.N) >= 0 {
            return false
        }

        /* Compute e */
        toHash := bytes32(r[i])
        toHash = append(toHash, bytes32(Px[i])...)
        toHash = append(toHash, m[i]...)

        bip0340Hash([]byte("BIP340/challenge"), toHash, h)
        toHashed := h.Sum(nil)

        e[i] = new(big.Int).SetBytes(toHashed)
        e[i].Mod(e[i], curveParams.N)

        rBytes := append([]byte{byte(3)}, pad(r[i].Bytes(), 32)...)
        Rx[i], Ry[i] = elliptic.UnmarshalCompressed(curve, rBytes)

        if Rx[i] == nil || Ry[i] == nil {
            rBytes = append([]byte{byte(2)}, pad(r[i].Bytes(), 32)...)
            Rx[i], Ry[i] = elliptic.UnmarshalCompressed(curve, rBytes)

            if Rx[i] == nil || Ry[i] == nil {
                return false
            }
        }
    }

    var temp1, temp2x, temp2y *big.Int
    var res1x, res1y, res2x, res2y *big.Int

    temp1 = big.NewInt(0)

    /* Multiply S by a */
    for i := 0; i < u; i++ {
        x := new(big.Int).Mul(a[i], s[i])

        temp1.Add(temp1, x)
        temp1.Mod(temp1, curve.Params().N)
    }

    /* Add S to the sum */
    res1x, res1y = pub0.Curve.ScalarBaseMult(temp1.Bytes())

    temp2x = Rx[0]
    temp2y = Ry[0]

    /* Now multiply R by a */
    for i := 1; i < u; i++ {
        x, y := curve.ScalarMult(Rx[i], Ry[i], a[i].Bytes())
        temp2x, temp2y = curve.Add(temp2x, temp2y, x, y)
    }

    /* Multiply e by 'a' */
    for i := 0; i < u; i++ {
        s := new(big.Int).Mul(a[i], e[i])
        s.Mod(s, curve.Params().N)

        x, y := curve.ScalarMult(Px[i], Py[i], s.Bytes())
        temp2x, temp2y = curve.Add(temp2x, temp2y, x, y)
    }

    res2x = temp2x
    res2y = temp2y

    if res2x.Cmp(res1x) != 0 || res2y.Cmp(res1y) != 0 {
        return false
    }

    return true
}

func pad(x []byte, n int) []byte {
    pad := make([]byte, n - len(x))
    return append(pad, x...)
}

func bytes32(x *big.Int) []byte {
    return pad(x.Bytes(), 32)
}

func bytes64(x *big.Int) []byte {
    return pad(x.Bytes(), 64)
}

func liftXEvenY(curve elliptic.Curve, x, y *big.Int) (*big.Int, *big.Int, error) {
    Px := new(big.Int).Set(x)
    Py := new(big.Int).Set(y)

    if new(big.Int).Mod(Py, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
        return Px, Py, nil
    } else {
        Py.Sub(curve.Params().P, Py)
        return Px, Py, nil
    }
}

func affYFromX(curve elliptic.Curve, x *big.Int) (*big.Int, *big.Int) {
    y1 := new(big.Int).Set(x)
    y2 := new(big.Int).Set(x)

    params := curve.Params()

    a := new(big.Int).Sub(params.P, big.NewInt(3))
    b := params.B

    /* Compute x^3 + ax + b */
    y1.Sqrt(y1)
    y1.Mul(y1, x)
    y2.Mul(y2, a)
    y1.Add(y1, y2)
    y1.Add(y1, b)

    /* Now compute the two possible square roots
     * realizing y^2 = x^3 + ax + b
     */
    y1.Sqrt(y2)

    return y1, y2
}
