package bign

import (
    "strings"
    "crypto"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/sha256"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/pem"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/hash/belt"
    "github.com/deatil/go-cryptobin/elliptic/bign"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func str(s string) string {
    var sb strings.Builder
    sb.Grow(len(s))
    s = strings.TrimPrefix(s, "0x")
    for _, c := range s {
        switch {
        case '0' <= c && c <= '9':
            sb.WriteRune(c)
        case 'a' <= c && c <= 'f':
            sb.WriteRune(c)
        case 'A' <= c && c <= 'F':
            sb.WriteRune(c)
        }
    }

    return sb.String()
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(str(s))
    return h
}

func fromBase64(s string) []byte {
    res, _ := base64.StdEncoding.DecodeString(s)
    return res
}

func toBigint(s string) *big.Int {
    result, _ := new(big.Int).SetString(str(s), 16)

    return result
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
    var _ crypto.Signer     = (*PrivateKey)(nil)
    var _ crypto.SignerOpts = (*SignerOpts)(nil)
}

func Test_NewPrivateKey(t *testing.T) {
    p224 := elliptic.P224()

    priv, err := GenerateKey(rand.Reader, p224)
    if err != nil {
        t.Fatal(err)
    }

    privBytes := PrivateKeyTo(priv)
    priv2, err := NewPrivateKey(p224, privBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey Equal error")
    }

    // ======

    pub := &priv.PublicKey

    pubBytes := PublicKeyTo(pub)
    pub2, err := NewPublicKey(p224, pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

func Test_SignerInterface(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_SignVerify(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")
    adata := MakeAdata([]byte("123"), []byte("typ"))

    sig, err := Sign(rand.Reader, priv, sha256.New, data, adata)
    if err != nil {
        t.Fatal(err)
    }

    res := Verify(pub, sha256.New, data, adata, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignVerify2(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")
    adata := MakeAdata([]byte("123"), []byte("typ"))

    sig, err := priv.Sign(rand.Reader, data, &SignerOpts{
        Hash: sha256.New,
        Adata: adata,
    })
    if err != nil {
        t.Fatal(err)
    }

    res, _ := pub.Verify(data, sig, &SignerOpts{
        Hash: sha256.New,
        Adata: adata,
    })
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignVerify_Dbign(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")
    adata := MakeAdata([]byte("123"), []byte("typ"))

    sig, err := Sign(nil, priv, sha256.New, data, adata)
    if err != nil {
        t.Fatal(err)
    }

    res := Verify(pub, sha256.New, data, adata, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignBytes(t *testing.T) {
    t.Run("P224 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P224(), sha256.New)
    })
    t.Run("P256 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P256(), sha256.New)
    })
}

func test_SignBytes(t *testing.T, c elliptic.Curve, h Hasher) {
    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")
    adata := MakeAdata([]byte("123"), []byte("typ"))

    sig, err := SignBytes(rand.Reader, priv, h, data, adata)
    if err != nil {
        t.Fatal(err)
    }

    res := VerifyBytes(pub, h, data, adata, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_Marshal(t *testing.T) {
    private, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    public := &private.PublicKey

    pubkey, err := MarshalPublicKey(public)
    if err != nil {
        t.Errorf("MarshalPublicKey error: %s", err)
    }

    parsedPub, err := ParsePublicKey(pubkey)
    if err != nil {
        t.Errorf("ParsePublicKey error: %s", err)
    }

    prikey, err := MarshalPrivateKey(private)
    if err != nil {
        t.Errorf("MarshalPrivateKey error: %s", err)
    }

    parsedPri, err := ParsePrivateKey(prikey)
    if err != nil {
        t.Errorf("ParsePrivateKey error: %s", err)
    }

    if !public.Equal(parsedPub) {
        t.Errorf("parsedPub error")
    }
    if !private.Equal(parsedPri) {
        t.Errorf("parsedPri error")
    }
}

var privPEM = `-----BEGIN PRIVATE KEY-----
MHsCAQAwEwYKKnAAAgAiZS0CAQYFK4EEACEEYTBfAgEBBBxPZ6xWgo5Awn3dOl+F
/XUnl/zuBgHd1zhpsh+2oTwDOgAEvEDlutuUuLmndmxscXDlOvzX3gN6O6gAjFAF
vf+VgGa6ioMWNToroz7CQrIwa1gcE1XUkFRzi4w=
-----END PRIVATE KEY-----
`

var pubPEM = `-----BEGIN PUBLIC KEY-----
MFEwEwYKKnAAAgAiZS0CAQYFK4EEACEDOgAEzcoYnYchmsKJIu3IIFF8X6L91Vv3
M2Nie29mugemzh6T00lM1bDeD1PqBs8weCpFFv20s62c3CQ=
-----END PUBLIC KEY-----
`

func Test_Marshal_Check(t *testing.T) {
    test_Marshal_Check(t, privPEM, pubPEM)
}

func test_Marshal_Check(t *testing.T, priv, pub string) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    parsedPub, err := ParsePublicKey(decodePEM(pub))
    if err != nil {
        t.Errorf("ParsePublicKey error: %s", err)
    }

    pubkey, err := MarshalPublicKey(parsedPub)
    if err != nil {
        t.Errorf("MarshalPublicKey error: %s", err)
    }

    pubPemCheck := encodePEM(pubkey, "PUBLIC KEY")
    assertEqual(pubPemCheck, pub, "test_Marshal_Check pubkey")

    // ===========

    parsedPriv, err := ParsePrivateKey(decodePEM(priv))
    if err != nil {
        t.Errorf("ParsePrivateKey error: %s", err)
    }

    privkey, err := MarshalPrivateKey(parsedPriv)
    if err != nil {
        t.Errorf("MarshalPrivateKey error: %s", err)
    }

    privPemCheck := encodePEM(privkey, "PRIVATE KEY")
    assertEqual(privPemCheck, priv, "test_Marshal_Check privkey")
}

func test_SignBytes_Check(t *testing.T) {
    privBytes := []byte{
        0x69, 0xe2, 0x73, 0xc2, 0x5f, 0x23, 0x79, 0x0c, 0x9e, 0x42, 0x32, 0x07, 0xed, 0x1f, 0x28, 0x34, 0x18, 0xf2, 0x74, 0x9c, 0x32, 0xf0, 0x33, 0x45, 0x67, 0x39, 0x73, 0x4b, 0xb8, 0xb5, 0x66, 0x1f,
    }
    sig := []byte{
        0xE3, 0x6B, 0x7F, 0x03, 0x77, 0xAE, 0x4C, 0x52, 0x40, 0x27, 0xC3, 0x87, 0xFA, 0xDF, 0x1B, 0x20,
        0xCE, 0x72, 0xF1, 0x53, 0x0B, 0x71, 0xF2, 0xB5, 0xFD, 0x3A, 0x8C, 0x58, 0x4F, 0xE2, 0xE1, 0xAE, 0xD2, 0x00, 0x82, 0xE3, 0x0C, 0x8A, 0xF6, 0x50, 0x11, 0xF4, 0xFB, 0x54, 0x64, 0x9D, 0xFD, 0x3D,
    }
    adata := []byte{
        0x00, 0x0b, 0x00, 0x00,
        0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
    }
    msg := fromHex("B194BAC80A08F53B366D008E58")

    // BIGN-BELT-HASH/bign256v1
    priv, err := NewPrivateKey(bign.P256v1(), privBytes)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey
    h := belt.New

    res := VerifyBytes(pub, h, msg, adata, sig)
    if !res {
        t.Error("Verify fail")
    }

}
