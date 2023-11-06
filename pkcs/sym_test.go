package pkcs

import (
    "io"
    "testing"
    "crypto/rand"

    pkcs8_pbes1 "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    pkcs8_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

type testCbcParams []byte

func Test_AES256CBC(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pass := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, pass); err != nil {
        t.Error(err.Error())
    }

    data := []byte("1awersdf")

    c := NewSym[testCbcParams](pkcs8_pbes2.AES256CBC)

    endata, parm, err := c.Encrypt(pass, data)
    assertError(err, "En")
    assertNotEmpty(endata, "En")

    dedata, err := c.Decrypt(pass, parm, endata)
    assertError(err, "En-de")
    assertNotEmpty(dedata, "En-de")

    assertEqual(dedata, data, "En")
}

type testPbeCBCParams struct {
    Salt           []byte
    IterationCount int
}

func Test_MD5AndDES(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pass := make([]byte, 8)
    if _, err := io.ReadFull(rand.Reader, pass); err != nil {
        t.Error(err.Error())
    }

    data := []byte("1awersdf")

    c := NewSym[testPbeCBCParams](pkcs8_pbes1.MD5AndDES)

    endata, parm, err := c.Encrypt(pass, data)
    assertError(err, "En")
    assertNotEmpty(endata, "En")

    dedata, err := c.Decrypt(pass, parm, endata)
    assertError(err, "En-de")
    assertNotEmpty(dedata, "En-de")

    assertEqual(dedata, data, "En")
}
