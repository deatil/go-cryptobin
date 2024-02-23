package gost_test

import (
    "fmt"
    "testing"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/gost"
)

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

func TestEqual(t *testing.T) {
    testOneCurve(t, gost.CurveIdGostR34102001TestParamSet())

    testOneCurve(t, gost.CurveIdtc26gost341012256paramSetA())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProAParamSet())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProBParamSet())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProCParamSet())

    testOneCurve(t, gost.CurveIdtc26gost341012512paramSetA())
    testOneCurve(t, gost.CurveIdtc26gost341012512paramSetB())
    testOneCurve(t, gost.CurveIdtc26gost341012512paramSetC())

    testOneCurve(t, gost.CurveIdGostR34102001CryptoProXchAParamSet())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProXchBParamSet())
}

func testOneCurve(t *testing.T, curue *gost.Curve) {
    t.Run(fmt.Sprintf("PKCS8 %s", curue), func(t *testing.T) {
        priv, err := gost.GenerateKey(rand.Reader, curue)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.Public().(*gost.PublicKey)

        pubDer, err := gost.MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }
        privDer, err := gost.MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }
        if len(pubDer) == 0 {
            t.Error("expected export key Der error: pub")
        }

        newPub, err := gost.ParsePublicKey(pubDer)
        if err != nil {
            t.Fatal(err)
        }
        newPriv, err := gost.ParsePrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal privekey error")
        }
        if !newPub.Equal(pub) {
            t.Error("Marshal public error")
        }
    })
}

func Test_Pkcs8(t *testing.T) {
    curue := gost.CurveIdGostR34102001TestParamSet()

    priv, err := gost.GenerateKey(rand.Reader, curue)
    if err != nil {
        t.Fatal(err)
    }

    pub := priv.Public().(*gost.PublicKey)

    pubDer, err := gost.MarshalPublicKey(pub)
    if err != nil {
        t.Fatal(err)
    }
    privDer, err := gost.MarshalPrivateKey(priv)
    if err != nil {
        t.Fatal(err)
    }

    if len(privDer) == 0 {
        t.Error("expected export key Der error: priv")
    }
    if len(pubDer) == 0 {
        t.Error("expected export key Der error: pub")
    }

    pri2 := encodePEM(privDer, "PRIVATE KEY")
    pub2 := encodePEM(pubDer, "PUBLIC KEY")

    if len(pri2) == 0 {
        t.Error("expected export key PEM error: priv")
    }
    if len(pub2) == 0 {
        t.Error("expected export key PEM error: pub")
    }
}
