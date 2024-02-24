package gost

import (
    "bytes"
    "testing"
    "crypto/rand"
)

// default ukm bytes
var defaultUkm = []byte("12345678")

func Test_KEK(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    priv1, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub1 := &priv1.PublicKey

    priv2, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub2 := &priv2.PublicKey

    key1, _ := KEK(priv1, pub2, NewUKM(defaultUkm))
    key2, _ := KEK(priv2, pub1, NewUKM(defaultUkm))

    if !bytes.Equal(key1, key2) {
        t.Error("key1 is not equal key2")
    }
}

func Test_VKO(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    ukm := decodeHex("5172be25f852a233")

    prv1 := decodeHex("1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
    priv1, err := NewPrivateKey(c, prv1)
    if err != nil {
        t.Fatal(err)
    }

    prv2 := decodeHex("5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
    priv2, err := NewPrivateKey(c, prv2)
    if err != nil {
        t.Fatal(err)
    }

    // kek := decodeHex("ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6")

    pub1 := &priv1.PublicKey
    pub2 := &priv2.PublicKey

    key1, _ := KEK(priv1, pub2, NewUKM(ukm))
    key2, _ := KEK(priv2, pub1, NewUKM(ukm))

    if !bytes.Equal(key1, key2) {
        t.Error("key1 is not equal key2")
    }
}
