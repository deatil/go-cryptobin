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
        GenerateRSAKey(512).
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

func Test_CreatePrivateKey_RSA(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            GenerateRSAKey(2048).
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_CreatePrivateKey_RSA")
        assertNotEmpty(key, "Test_CreatePrivateKey_RSA")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            GenerateECDSAKey("P256").
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_CreatePrivateKey_RSA")
        assertNotEmpty(key, "Test_CreatePrivateKey_RSA")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            GenerateEdDSAKey().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_CreatePrivateKey_RSA")
        assertNotEmpty(key, "Test_CreatePrivateKey_RSA")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            GenerateSM2Key().
            CreatePrivateKey()
        key := obj.ToKeyString()

        assertError(obj.Error(), "Test_CreatePrivateKey_RSA")
        assertNotEmpty(key, "Test_CreatePrivateKey_RSA")
    })

}
