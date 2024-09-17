package bign

import (
    "testing"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func testCurve(t *testing.T, curve elliptic.Curve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test")
    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

func Test_All(t *testing.T) {
    t.Run("P256v1", func(t *testing.T) {
        testCurve(t, P256v1())
    })

    t.Run("P384v1", func(t *testing.T) {
        testCurve(t, P384v1())
    })

    t.Run("P512v1", func(t *testing.T) {
        testCurve(t, P512v1())
    })
}

