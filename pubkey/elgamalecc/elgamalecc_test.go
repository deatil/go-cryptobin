package elgamalecc

import (
    "bytes"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/elliptic"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Encrypt(t *testing.T) {
    c := elliptic.P256()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    C1x, C1y, C2, err := Encrypt(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    p, _ := Decrypt(priv, C1x, C1y, C2)
    if !bytes.Equal(data, p) {
        t.Errorf("Test_Encrypt fail, got %x, want %x", p, data)
    }

}

func Test_Encrypt_Check(t *testing.T) {
    c := elliptic.P256()

    x := fromHex("67e87b98e8a4383098fedb448c1f3d278bebba50525dec57c0576c605bfffdda")
    Y := fromHex("045ec79d828a77af85aa9c8ef3ba5afd7674376d6b134d14b10bb4afb7fd0952b0e894f696b38096ff547bbd0a0f1d14a195f2fc9ce951901fe2925560f29d98c0")

    priv, err := NewPrivateKey(c, x)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := NewPublicKey(c, Y)
    if err != nil {
        t.Fatal(err)
    }

    data := []byte("Hello")

    C1x, C1y, C2, err := Encrypt(rand.Reader, pub, data)
    if err != nil {
        t.Fatal(err)
    }

    // C1Bytes := elliptic.Marshal(pub.Curve, C1x, C1y)
    // C1=04af7035184190ce72b1ee000ec8f18927a664c23358ce4d41ff757283a5846bb58c19c551753ea0af151c31c1a3698606af565c122a387dbe67d7fa5deba2393f
    // t.Errorf("C1Bytes: %x", C2)

    p, _ := Decrypt(priv, C1x, C1y, C2)
    if !bytes.Equal(data, p) {
        t.Errorf("ElgamalDecrypt fail, got %x, want %x", p, data)
    }

    C1 := fromHex("04af7035184190ce72b1ee000ec8f18927a664c23358ce4d41ff757283a5846bb58c19c551753ea0af151c31c1a3698606af565c122a387dbe67d7fa5deba2393f")
    C22, _ := new(big.Int).SetString("64998866770800537035816591092081487793369751526287129670052291837083837454710935744289325621649282383337514803150244272041445838052262073601284819093853352", 10)

    C1x2, C1y2 := elliptic.Unmarshal(priv.Curve, C1)
    p2, _ := Decrypt(priv, C1x2, C1y2, C22)
    if !bytes.Equal(data, p2) {
        t.Errorf("Test_Encrypt_Check fail, got %x, want %x", p2, data)
    }
}
