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

func Test_Public(t *testing.T) {
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

var privBytes = "2367b29bceaca04d6fe50d959dee3d706f3a5f605ce5aac0205c54cdda59145c573b932814c7405770cd46171a0eb44c911f8e851adeefcc77e5841bf86e0b6486dd"
var pubBytes = "72c86f2d561e5d3db6e350a92b0287a2434207b3869cd013ccbf1034c82b647b7548bc927975da76e750c991a443a11d23a264888b36c73e6a48a2602f777d3ff081"

func Test_Key(t *testing.T) {
    privPlain := fromHex(privBytes)
    pubPlain := fromHex(pubBytes)

    priv, err := NewKeyFromSeed(privPlain)
    if err != nil {
        t.Fatal(err)
    }

    pub0 := &priv.PublicKey

    pub1, err := NewPublicKey(pubPlain)
    if err != nil {
        t.Fatal(err)
    }

    cryptobin_test.Equal(t, pub0, pub1)
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
                t.Error("Verify fail")
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
        secretKey: fromHex("22713dc2f3d8a4611e9266d8a2a9e3d237505dc34c65d87d598b9a4e6c41b35e3d090458e66c8213a4af011e5614377960c99d9f84e379fdd1f1e168b163b5d93012"),
        publicKey: fromHex("020006be6a2ea17441c94e25799154b049ebae2fedcedfb27355ab03f9eb802d239677c340392fe113ffb18138b95dc8ba3efd766401cabfc4cc30d0ccdce7b178d954"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("e6309d7d752de236179d694954f9345a73b1abcbe7ebde16e5e0fa1a4ed60003839a13f03fe1fccfecdac66614b8aff731e7956678be247b8f19795b20351a578301780dd7e6d41db086ef9bdc4658cbcc3d86d259b7e36ea399b075da86f2559489c64f59d196c5a439b3c5442609912dee28721d82dd08c71884b7f406961510110e00"),
        verification: true,
    },

    // fail
    {
        secretKey: fromHex("22713dc2f3d8a4611e9266d8a2a9e3d237505dc34c65d87d598b9a4e6c41b35e3d090458e66c8213a4af011e5614377960c99d9f84e379fdd1f1e168b163b5d93012"),
        publicKey: fromHex("020006be6a2ea17441c94e25799154b049ebae2fedcedfb27355ab03f9eb802d239677c340392fe113ffb18138b95dc8ba3efd766401cabfc4cc30d0ccdce7b178d954"),
        message:   fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        signature: fromHex("3bd0454bd7a48f25fa40e0ebd76c1eb48e7fff63f606f35f9a8de9fc6d8fde0f75c10c0d97b7dc3001c5da6da681ff95d1a6ace65c19134ca727b99b1c349752ee01e8c9d1f325ab430511bcbf1e009d37418f56f132383ed55e43d97c04feff5a6f875fa64458ab73f9e4d1ad93cc978a7939a9afe532e8e6162b7bcb986f04a2282a00"),
        verification: false,
    },
}
