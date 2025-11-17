package ed521

import (
    "fmt"
    "bytes"
    "testing"
    "crypto"
    "crypto/rand"
    "crypto/elliptic"
    "encoding/pem"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/elliptic/ed521"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

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

func Test_Interface(t *testing.T) {
    var _ crypto.Signer = (*PrivateKey)(nil)
}

func Test_SignerInterface(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_NewPrivateKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    privBytes := PrivateKeyTo(priv)
    priv2, err := NewPrivateKey(privBytes)
    if err != nil {
        t.Fatal(err)
    }

    cryptobin_test.Equal(t, priv2, priv, "NewPrivateKey Equal error")

    // ======

    pub := &priv.PublicKey

    pubBytes := PublicKeyTo(pub)
    pub2, err := NewPublicKey(pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

func aTest_Public(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey
    pub2 := priv.Public()

    if !pub.Equal(pub2) {
        t.Error("Export Public Equal fail")
    }
}

func Test_Equal(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    priv2, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub2 := &priv2.PublicKey

    if priv.Equal(priv2) {
        t.Error("PrivateKey should not Equal")
    }
    if pub.Equal(pub2) {
        t.Error("PublicKey should not Equal")
    }
}

func Test_SignVerify(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := priv.Sign(rand.Reader, data, nil)
    if err != nil {
        t.Fatal(err)
    }

    res := pub.Verify(data, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignVerify2(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := Sign(rand.Reader, priv, data)
    if err != nil {
        t.Fatal(err)
    }

    res, _ := Verify(pub, data, sig)
    cryptobin_test.True(t, res)
}

func Test_SignVerify3(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := priv.Sign(rand.Reader, data, &Options{
        Scheme: ED521Ph,
    })
    if err != nil {
        t.Fatal(err)
    }

    err = VerifyWithOptions(pub, data, sig, &Options{
        Scheme: ED521Ph,
    })
    if err != nil {
        t.Error("Verify fail")
    }
}

func Test_SignVerify33(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := priv.Sign(rand.Reader, data, &Options{
        Scheme:  ED521Ph,
        Context: "ed521 Context",
    })
    if err != nil {
        t.Fatal(err)
    }

    err = VerifyWithOptions(pub, data, sig, &Options{
        Scheme:  ED521Ph,
        Context: "ed521 Context",
    })
    if err != nil {
        t.Error("Verify fail")
    }
}

func Test_SignVerify_fail(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := Sign(rand.Reader, priv, data)
    if err != nil {
        t.Fatal(err)
    }

    sig[len(sig)-6] = sig[len(sig)-6] + 1

    res, _ := Verify(pub, data, sig)
    cryptobin_test.False(t, res)
}

func Test_Marshal(t *testing.T) {
    curve := ed521.ED521()

    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pubBytes := ed521.Marshal(pub.Curve, pub.X, pub.Y)
    pubBytes2 := ed521.MarshalCompressed(pub.Curve, pub.X, pub.Y)

    // t.Errorf("\n k: %x, \n p: %x \n", priv.D, pubBytes2)

    cryptobin_test.NotEmpty(t, pubBytes)
    cryptobin_test.NotEmpty(t, pubBytes2)

    x, y := elliptic.Unmarshal(curve, pubBytes)
    pub2 := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    x2, y2 := elliptic.UnmarshalCompressed(curve, pubBytes2)
    pub3 := &PublicKey{
        Curve: curve,
        X: x2,
        Y: y2,
    }

    cryptobin_test.Equal(t, pub, pub2)
    cryptobin_test.Equal(t, pub, pub3)
}

func Test_Vec_Check(t *testing.T) {
    for i, td := range testSigVec {
        t.Run(fmt.Sprintf("index %d", i), func(t *testing.T) {
            curve := ed521.ED521()

            if len(td.secretKey) > 0 {
                priv, err := NewPrivateKey(td.secretKey)
                if err != nil {
                    t.Fatal(err)
                }

                pub := &priv.PublicKey

                pubBytes := ed521.MarshalCompressed(pub.Curve, pub.X, pub.Y)

                // check publicKey
                if !bytes.Equal(pubBytes, td.publicKey) {
                    t.Errorf("PublicKey got: %x, want: %x", pubBytes, td.publicKey)
                }

                // check sig
                sig, err := priv.Sign(rand.Reader, td.message, nil)
                if err != nil {
                    t.Error("encode sig fail")
                }

                if bytes.Equal(sig, td.signature) != td.verification {
                    t.Errorf("sig fail, got: %x, want: %x", sig, td.signature)
                }

            }

            x, y := ed521.UnmarshalCompressed(curve, td.publicKey)
            if x == nil || y == nil {
                t.Fatal("publicKey error")
            }

            pubkey := &PublicKey{
                Curve: curve,
                X: x,
                Y: y,
            }

            veri := pubkey.Verify(td.message, td.signature)
            if veri != td.verification {
                t.Error("VerifyASN1 fail")
            }

        })
    }

}

type testVec struct {
    secretKey []byte
    publicKey []byte
    message   []byte
    signature []byte
    verification bool
}

var testSigVec = []testVec{
    {
        secretKey: fromHex("313e78bd2f5eb3f0a9ee0120496cb3c891a3d4f79d1b8c01f81cd7d70bcadefbb941a3058dabe6b5dbe559b6f5331cc0087af6a367d47555d5cb95a8dacea4d167"),
        publicKey: fromHex("03015c5b1c1dbdb4e81225cfd8bbfa14b01148b3d3741e9dc0d16c4d40ac8d72eb6752a9015c6aa5c87239491d1d49f292b67a78987283f430af271572e030f9d7f862"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("a6659ed7213f736f46c10c983329523cf246fd0126406bd533783f80b33893b52c899c37e5f8012b378214b983fad7cde1b1d528977a4892cb8abc4872a59d18c500782fdeafb0c93ea7a4f8b16028df15ff05644ede3698ca88c1602ede83c68342aaa013cec1ea2e8d65d4bed0764f8b42e9548a2e41d49786aa0ad2ed782d6c353200"),
        verification: true,
    },

    // fail
    {
        secretKey: fromHex("22713dc2f3d8a4611e9266d8a2a9e3d237505dc34c65d87d598b9a4e6c41b35e3d090458e66c8213a4af011e5614377960c99d9f84e379fdd1f1e168b163b5d930"),
        publicKey: fromHex("0300d4a01d6c5cd88d226e33ab966991d6939c72d7012f209a7fc7006d0b9f93df99e8ab5543cb5d27a2818f27cad1648bfecdd49e7772ded70ee7043444a518683019"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("a6659ed7213f736f46c10c983329523cf246fd0126406bd533783f80b33893b52c899c37e5f8012b378214b983fad7cde1b1d528977a4892cb8abc4872a59d18c500782fdeafb0c93ea7a4f8b16028df15ff05644ede3698ca88c1602ede83c68342aaa013cec1ea2e8d65d4bed0764f8b42e9548a2e41d49786aa0ad2ed782d6c353200"),
        verification: false,
    },
}
