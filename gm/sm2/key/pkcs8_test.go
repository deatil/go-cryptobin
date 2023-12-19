package key

import (
    "testing"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_PKCS8(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    priv1, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pem1, err := MarshalPKCS8PrivateKey(priv1)
    if err != nil {
        t.Fatal(err)
    }

    if len(pem1) == 0 {
        t.Error("priv pem make error")
    }

    priv2, err := ParsePKCS8PrivateKey(pem1)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(priv2, priv1, "PKCS8")
}

func Test_PublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    priv1, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    pub1 := &priv1.PublicKey

    pem1, err := MarshalPublicKey(pub1)
    if err != nil {
        t.Fatal(err)
    }

    if len(pem1) == 0 {
        t.Error("pub pem make error")
    }

    pub2, err := ParsePublicKey(pem1)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(pub2, pub1, "PublicKey")
}
