package kcdsa

import (
    "fmt"
    "bufio"
    "testing"
    "strings"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/hash/has160"
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

var testBitsize = 256
var testProbability = 64

func Test_GenerateKey2(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pri := &priv
    var _ crypto.Signer = pri

    assertNotEmpty(priv, "GenerateKey")
}

func Test_Sign(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pub := &priv.PublicKey

    assertNotEmpty(priv, "Sign")

    data := []byte("123tesfd!dfsign")

    r, s, err := Sign(rand.Reader, &priv, sha256.New224, data)
    assertError(err, "Sign-sig-Error")

    veri := Verify(pub, sha256.New224, data, r, s)
    assertBool(veri, "Sign-veri")
}

func Test_Sign2(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    pub := &priv.PublicKey

    assertNotEmpty(priv, "Sign")

    data := []byte("123tesfd!dfsign")

    sig, err := priv.Sign(rand.Reader, data, &SignerOpts{
        Hash: sha256.New224,
    })
    assertError(err, "Sign-sig-Error")

    veri, _ := pub.Verify(data, sig, &SignerOpts{
        Hash: sha256.New224,
    })
    assertBool(veri, "Sign-veri")
}

func test_GenerateKey(t *testing.T) *PrivateKey {
    assertError := cryptobin_test.AssertErrorT(t)

    var priv PrivateKey
    err := GenerateParameters(&priv.PublicKey.Parameters, rand.Reader, A2048B224SHA224)
    assertError(err, "GenerateParameters-Error")

    err = GenerateKey(&priv, rand.Reader)
    assertError(err, "GenerateKey-Error")

    return &priv
}

func Test_MarshalPKCS8(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)

    pri := test_GenerateKey(t)
    pub := &pri.PublicKey

    assertNotEmpty(pri, "MarshalPKCS8")

    //===============

    pubDer, err := MarshalPKCS8PublicKey(pub)
    assertError(err, "MarshalPKCS8PublicKey-pub-Error")
    assertNotEmpty(pubDer, "MarshalPKCS8PublicKey")

    parsedPub, err := ParsePKCS8PublicKey(pubDer)
    assertError(err, "ParsePKCS8PublicKey-pub-Error")
    assertEqual(parsedPub, pub, "MarshalPKCS8")

    //===============

    priDer, err := MarshalPKCS8PrivateKey(pri)
    assertError(err, "MarshalPKCS8PrivateKey-pri-Error")
    assertNotEmpty(priDer, "MarshalPKCS8PrivateKey")

    parsedPri, err := ParsePKCS8PrivateKey(priDer)
    assertError(err, "ParsePKCS8PrivateKey-pri-Error")
    assertEqual(parsedPri, pri, "ParsePKCS8PrivateKey")
}

var rnd = bufio.NewReaderSize(rand.Reader, 1<<15)

type testCase struct {
    Sizes ParameterSizes
    Hash Hasher

    M []byte

    Seedb []byte
    J     *big.Int
    Count int
    P, Q  *big.Int

    H []byte
    G *big.Int

    XKEY []byte
    X    *big.Int
    Y, Z *big.Int

    KKEY *big.Int
    R    *big.Int
    S    *big.Int

    Fail bool
}

func Test_SignVerify_With_BadPublicKey(t *testing.T) {
    for idx, tc := range testCaseTTAK {
        tc2 := testCaseTTAK[(idx+1)%len(testCaseTTAK)]

        pub := PublicKey{
            Parameters: Parameters{
                P: tc2.P,
                Q: tc2.Q,
                G: tc2.G,
            },
            Y: tc2.Y,
        }

        ok := Verify(&pub, tc.Hash, tc.M, tc.R, tc.S)
        if ok {
            t.Errorf("Verify unexpected success with non-existent mod inverse of Q")
            return
        }
    }
}

func Test_Signing_With_DegenerateKeys(t *testing.T) {
    badKeys := []struct {
        p, q, g, y, x string
    }{
        {"00", "01", "00", "00", "00"},
        {"01", "ff", "00", "00", "00"},
    }

    msg := []byte("testing")
    for i, test := range badKeys {
        priv := PrivateKey{
            PublicKey: PublicKey{
                Parameters: Parameters{
                    P: toBigint(test.p),
                    Q: toBigint(test.q),
                    G: toBigint(test.g),
                },
                Y: toBigint(test.y),
            },
            X: toBigint(test.x),
        }

        if _, _, err := Sign(rand.Reader, &priv, sha256.New224, msg); err == nil {
            t.Errorf("#%d: unexpected success", i)
            return
        }
    }
}

func Test_KCDSA(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping parameter generation test in short mode")
    }

    t.Run("A2048B224SHA224", testKCDSA(A2048B224SHA224, sha256.New224))
    t.Run("A2048B224SHA256", testKCDSA(A2048B224SHA256, sha256.New))
    t.Run("A2048B256SHA256", testKCDSA(A2048B256SHA256, sha256.New))
    t.Run("A3072B256SHA256", testKCDSA(A3072B256SHA256, sha256.New))
    t.Run("A1024B160HAS160", testKCDSA(A1024B160HAS160, has160.New))
}

func testKCDSA(sizes ParameterSizes, h Hasher) func(*testing.T) {
    return func(t *testing.T) {
        d, ok := GetSizes(sizes)
        if !ok {
            t.Errorf("domain not found")
            return
        }

        var priv PrivateKey
        params := &priv.Parameters

        err := GenerateParameters(params, rand.Reader, sizes)
        if err != nil {
            t.Error(err)
            return
        }

        if params.P.BitLen() > d.A {
            t.Errorf("params.BitLen got:%d want:%d", params.P.BitLen(), d.A)
            return
        }

        if params.Q.BitLen() > d.B {
            t.Errorf("q.BitLen got:%d want:%d", params.Q.BitLen(), d.B)
            return
        }

        err = GenerateKey(&priv, rand.Reader)
        if err != nil {
            t.Errorf("error generating key: %s", err)
            return
        }

        testSignAndVerify(t, &priv, h)
        testSignAndVerifyASN1(t, &priv, h)
    }
}

func testSignAndVerify(t *testing.T, priv *PrivateKey, h Hasher) {
    data := []byte("testing")
    r, s, err := Sign(rand.Reader, priv, h, data)
    if err != nil {
        t.Errorf("error signing: %s", err)
        return
    }

    ok := Verify(&priv.PublicKey, h, data, r, s)
    if !ok {
        t.Error("Verify failed")
        return
    }

    data[0] ^= 0xff
    if Verify(&priv.PublicKey, h, data, r, s) {
        t.Errorf("Verify always works!")
    }
}

func testSignAndVerifyASN1(t *testing.T, priv *PrivateKey, h Hasher) {
    data := []byte("testing")
    sig, err := SignASN1(rand.Reader, priv, h, data)
    if err != nil {
        t.Errorf("error signing: %s", err)
        return
    }

    if !VerifyASN1(&priv.PublicKey, h, data, sig) {
        t.Errorf("VerifyASN1 failed")
    }

    data[0] ^= 0xff
    if VerifyASN1(&priv.PublicKey, h, data, sig) {
        t.Errorf("VerifyASN1 always works!")
    }
}

func verifyTestCases(t *testing.T, testCases []testCase) {
    for i, tc := range testCases {
        t.Run(fmt.Sprintf("test index %d", i), func(t *testing.T) {
            pub := PublicKey{
                Parameters: Parameters{
                    P: tc.P,
                    Q: tc.Q,
                    G: tc.G,
                },
                Y: tc.Y,
            }

            ok := Verify(&pub, tc.Hash, tc.M, tc.R, tc.S)
            if ok == tc.Fail {
                t.Errorf("verify failed")
                return
            }
        })
    }
}
