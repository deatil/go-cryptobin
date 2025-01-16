package ca

import (
    "testing"
    "encoding/pem"
    "crypto/x509/pkix"

    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_CreateCA(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCA(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        }, 2, "SHA256WithRSA").
        CreateCA()
    key := obj.ToKeyString()

    assertError(obj.Error(), "Test_CreateCA")
    assertNotEmpty(key, "Test_CreateCA")

    // ===========

    block, _ := pem.Decode([]byte(key))

    cert, err := cryptobin_x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

func Test_GenerateKey(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("RSA").
            WithBits(2048).
            GenerateKey().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(key, "Test_GenerateKey")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("ECDSA").
            SetCurve("P256").
            GenerateKey().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(key, "Test_GenerateKey")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("EdDSA").
            GenerateKey().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(key, "Test_GenerateKey")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("SM2").
            GenerateKey().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(key, "Test_GenerateKey")
    })

}

func Test_GenerateKey2(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            GenerateRSAKey(2048).
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(key, "Test_GenerateKey2")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            GenerateECDSAKey("P256").
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(key, "Test_GenerateKey2")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            GenerateEdDSAKey().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(key, "Test_GenerateKey2")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            GenerateSM2Key().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(key, "Test_GenerateKey2")
    })

}
