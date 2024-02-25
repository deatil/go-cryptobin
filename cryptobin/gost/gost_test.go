package gost

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var testPEMCiphers = []string{
    "DESEDE3CBC",
    "AES256CBC",
}

func Test_CreatePKCS8PrivateKeyWithPassword(t *testing.T) {
    gen := GenerateKey("CurveIdGostR34102001CryptoProAParamSet")

    for _, cipher := range testPEMCiphers {
        test_CreatePKCS8PrivateKeyWithPassword(t, gen, cipher)
    }
}

func test_CreatePKCS8PrivateKeyWithPassword(t *testing.T, gen Gost, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(cipher, func(t *testing.T) {
        pass := make([]byte, 12)
        _, err := rand.Read(pass)
        if err != nil {
            t.Fatal(err)
        }

        prikey := gen.GetPrivateKey()

        pri := gen.
            CreatePKCS8PrivateKeyWithPassword(string(pass), cipher).
            ToKeyString()

        assertError(gen.Error(), "Test_CreatePKCS8PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS8PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS8PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS8PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS8PrivateKeyWithPassword")
    })
}

func Test_Sign(t *testing.T) {
    types := []string{
        "CurveIdGostR34102001CryptoProAParamSet",
        "CurveIdtc26gost34102012256paramSetC",
    }

    for _, name := range types {
        t.Run(name, func(t *testing.T) {
            gen := GenerateKey(name)
            test_Sign(t, gen)
        })
    }
}

func test_Sign(t *testing.T, gen Gost) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "Sign-Sign")
    assertNotEmpty(signed, "Sign-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        Verify([]byte(data))

    assertError(objVerify.Error(), "Sign-Verify")
    assertBool(objVerify.ToVerify(), "Sign-Verify")
}

func Test_MakeKey(t *testing.T) {
    gen := GenerateKey("CurveIdtc26gost34102012256paramSetC")

    prikey := gen.
        CreatePKCS8PrivateKey().
        ToKeyString()

    if len(prikey) == 0 {
        t.Error("make prikey fail")
    }
}
