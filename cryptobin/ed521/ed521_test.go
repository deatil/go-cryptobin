package ed521

import (
    "fmt"
    "crypto"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    testPrikey = `-----BEGIN PRIVATE KEY-----
MFcCAQAwDgYKKwYBBAGC3CwCAQYABEIAKG1VJuFCsAxsDCr6uBrNfQaYCPOvGu7D
kLJ/CQkUhCmg0DKrQrhLWwwp6TXUekXr5LOlo0rzl7frT+g46YSbiQI=
-----END PRIVATE KEY-----
    `
    testPubkey = `-----BEGIN PUBLIC KEY-----
MFUwDgYKKwYBBAGC3CwCAQYAA0MAmni8ls4g54Kqpk5gMM7/dscHeV6nm4Eq8zY3
OX1BYZZaEp6KX4P7PhwHv5ZYhHZK23bH4O483nRnAkitNHNKMLoA
-----END PUBLIC KEY-----
`

    testPrikeyEn = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHDMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAUciNePUdR/1Yam7+s
ESzEAgInEDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQPSnhje7xky4oXvb4
JRNkqARgHbRbcy46pxZL3nMYvZDHrgAYmdzSMaDNXqtASgKtc2YMH0vi/3Ej9ai9
OWfCAC6k7Jf8QmH4SSV73ubvcpi+WXGMqqAnPh52HWN7apIyrUvBRz2n2bz5EEBp
FbfFSxL1
-----END ENCRYPTED PRIVATE KEY-----
    `
    testPubkeyEn = `-----BEGIN PUBLIC KEY-----
MFUwDgYKKwYBBAGC3CwCAQYAA0MAlFBP2O8rujvdW3bE3SoLJfGe3P33p0RyHZkW
Rvx91ZZQXrNe4vEgylU2BcQm3nXMm2Z8rB6fWr9fEKu57WU6ENgB
-----END PUBLIC KEY-----
    `
)

func testED521Sign(t *testing.T, opts *Options) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := []byte("test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass3333333333333333333333333333333333333333333333333333test-pa2222222222222222222222222222222222222222222sstest-passt111111111111111111111111111111111est-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passt-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass")

    hashed := FromBytes(data).
        FromPrivateKey([]byte(testPrikey)).
        WithOptions(opts).
        Sign()
    hashedData := hashed.ToBase64String()

    assertNoError(hashed.Error(), "ED521Sign-Sign")
    assertNotEmpty(hashedData, "ED521Sign-Sign")

    // ===

    dehashed := FromBase64String(hashedData).
        FromPublicKey([]byte(testPubkey)).
        WithOptions(opts).
        Verify(data)
    dehashedVerify := dehashed.ToVerify()

    assertNoError(dehashed.Error(), "ED521Sign-Verify")
    assertTrue(dehashedVerify, "ED521Sign-Verify")
}

func Test_ED521Sign(t *testing.T) {
    ctx := "ase3ertygfa1"

    optses := []*Options{
        &Options{
            Hash:    crypto.Hash(0),
            Context: ctx,
            Scheme:  SchemeED521,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: ctx,
            Scheme:  SchemeED521Ph,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED521,
        },
        &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED521Ph,
        },
    }

    i := 1
    for _, opts := range optses {
        t.Run(fmt.Sprintf("ED521 index %d", i), func(t *testing.T) {
            testED521Sign(t, opts)
        })

        i += 1
    }
}

func Test_CreateKey(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    obj := New().GenerateKey()

    objPriKey := obj.CreatePrivateKey()
    priKey := objPriKey.ToKeyString()

    assertNoError(objPriKey.Error(), "CreateKey-priKey")
    assertNotEmpty(priKey, "CreateKey-priKey")

    objPriKeyEn := obj.CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
    priKeyEn := objPriKeyEn.ToKeyString()

    assertNoError(objPriKeyEn.Error(), "CreateKey-priKeyEn")
    assertNotEmpty(priKeyEn, "CreateKey-priKeyEn")

    objPubKey := obj.CreatePublicKey()
    pubKey := objPubKey.ToKeyString()

    assertNoError(objPubKey.Error(), "CreateKey-pubKey")
    assertNotEmpty(pubKey, "CreateKey-pubKey")

    // t.Errorf("pri: %s, pub: %s, prien: %s \n", priKey, pubKey, priKeyEn)
}

func Test_CheckKeyPair(t *testing.T) {
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    check := New().
        FromPublicKey([]byte(testPubkey)).
        FromPrivateKey([]byte(testPrikey))
    checkData := check.CheckKeyPair()

    assertNoError(check.Error(), "CheckKeyPair")
    assertTrue(checkData, "CheckKeyPair")

    // ==========

    checkEn := New().
        FromPublicKey([]byte(testPubkeyEn)).
        FromPrivateKeyWithPassword([]byte(testPrikeyEn), "123")
    checkDataEn := checkEn.CheckKeyPair()

    assertNoError(checkEn.Error(), "CheckKeyPair-EnPri")
    assertTrue(checkDataEn, "CheckKeyPair-EnPri")
}

func Test_MakePublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    ed := New().FromPrivateKey([]byte(testPrikey))
    newPubkey := ed.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    assertNoError(ed.Error(), "MakePublicKey")
    assertEqual(newPubkey, testPubkey, "MakePublicKey")
}

func Test_CheckKeyString(t *testing.T) {
    ed := New().GenerateKey()

    priString := ed.GetPrivateKeyString()
    pubString := ed.GetPublicKeyString()

    cryptobin_test.NotEmpty(t, priString)
    cryptobin_test.NotEmpty(t, pubString)

    pri := New().
            FromPrivateKeyString(priString).
            GetPrivateKey()
    pub := New().
            FromPublicKeyString(pubString).
            GetPublicKey()

    cryptobin_test.Equal(t, ed.GetPrivateKey(), pri)
    cryptobin_test.Equal(t, ed.GetPublicKey(), pub)
}
