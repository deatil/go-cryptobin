package ecgdsa

import (
    "errors"
    "testing"
    "crypto/dsa"
    "crypto/rsa"
    "crypto/rand"
    "crypto/elliptic"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GenKey(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey(t, c)
        })
    }
}

func test_GenKey(t *testing.T, keyType string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj.Error(), "Test_GenKey")

    {
        prikey := obj.CreateOpenSSHPrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreateOpenSSHPublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromOpenSSHPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromOpenSSHPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreateOpenSSHPrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromOpenSSHPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey2(t *testing.T) {
    cases := []string{
        "RSA",
        "DSA",
        "ECDSA",
        "EdDSA",
        "SM2",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey2(t, c)
        })
    }
}

func test_GenKey2(t *testing.T, keyType string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().SetPublicKeyType(keyType).GenerateKey()
    assertError(obj.Error(), "Test_GenKey")

    {
        assertEqual(obj.GetPrivateKeyType().String(), keyType, "Test_GenKey-GetPrivateKeyType")
        assertEqual(obj.GetPublicKeyType().String(), keyType, "Test_GenKey-GetPublicKeyType")
    }

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-newSSH3")
    }
}

func Test_GenKey3(t *testing.T) {
    cases := []PublicKeyType{
        KeyTypeRSA,
        KeyTypeDSA,
        KeyTypeECDSA,
        KeyTypeEdDSA,
        KeyTypeSM2,
    }

    for _, c := range cases {
        t.Run(c.String(), func(t *testing.T) {
            test_GenKey3(t, c)
        })
    }
}

func test_GenKey3(t *testing.T, keyType PublicKeyType) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    newOpts := func(ktype PublicKeyType) Options {
        opt := Options{
            PublicKeyType:  ktype,
            ParameterSizes: dsa.L1024N160,
            Curve:          elliptic.P256(),
            Bits:           2048,
        }

        return opt
    }

    obj := GenerateKey(newOpts(keyType))
    assertError(obj.Error(), "Test_GenKey3")

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey3-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey3-PublicKey")

        // t.Errorf("%s, %s \n", string(prikey), string(pubkey))

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey3-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey3-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey3-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey3-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey3-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey3-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey3-newSSH3")
    }
}

func Test_GenKey5(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey()
    assertError(obj.Error(), "Test_GenKey5")

    {
        prikey := obj.CreatePrivateKey().ToKeyBytes()
        assertNotEmpty(prikey, "Test_GenKey5-PrivateKey")

        pubkey := obj.CreatePublicKey().ToKeyBytes()
        assertNotEmpty(pubkey, "Test_GenKey5-PublicKey")

        newSSH := New().FromPrivateKey(prikey)
        assertError(newSSH.Error(), "Test_GenKey5-newSSH")

        assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey3-newSSH")

        newSSH2 := New().FromPublicKey(pubkey)
        assertError(newSSH2.Error(), "Test_GenKey5-newSSH2")

        assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey5-newSSH2")
    }

    {
        password := []byte("test-password")

        prikey3 := obj.CreatePrivateKeyWithPassword(password).ToKeyBytes()
        assertNotEmpty(prikey3, "Test_GenKey5-PrivateKey 3")

        newSSH3 := New().FromPrivateKeyWithPassword(prikey3, password)
        assertError(newSSH3.Error(), "Test_GenKey5-newSSH3")

        assertEqual(newSSH3.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey5-newSSH3")
    }
}

func Test_GenKey_ECDSA(t *testing.T) {
    cases := []string{
        "P256",
        "P384",
        "P521",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey_ECDSA(t, c)
        })
    }
}

func test_GenKey_ECDSA(t *testing.T, curve string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("ECDSA").
        SetCurve(curve).
        GenerateKey()
    assertError(obj.Error(), "Test_GenKey_ECDSA")

    prikey := obj.CreateOpenSSHPrivateKey().ToKeyBytes()
    assertNotEmpty(prikey, "Test_GenKey_ECDSA-PrivateKey")

    pubkey := obj.CreateOpenSSHPublicKey().ToKeyBytes()
    assertNotEmpty(pubkey, "Test_GenKey_ECDSA-PublicKey")

    newSSH := New().FromOpenSSHPrivateKey(prikey)
    assertError(newSSH.Error(), "Test_GenKey_ECDSA-newSSH")

    assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey_ECDSA-newSSH")

    newSSH2 := New().FromOpenSSHPublicKey(pubkey)
    assertError(newSSH2.Error(), "Test_GenKey_ECDSA-newSSH2")

    assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey_ECDSA-newSSH2")
}

func Test_GenKey_ECDSA_With_Comment(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    comment := "test-comment"

    obj := New().
        SetPublicKeyType("ECDSA").
        GenerateKey()
    assertError(obj.Error(), "Test_GenKey_ECDSA_With_Comment")

    prikey := obj.WithComment(comment).
        CreateOpenSSHPrivateKey().
        ToKeyBytes()
    assertNotEmpty(prikey, "Test_GenKey_ECDSA_With_Comment-PrivateKey")

    pubkey := obj.WithComment(comment).
        CreateOpenSSHPublicKey().
        ToKeyBytes()
    assertNotEmpty(pubkey, "Test_GenKey_ECDSA_With_Comment-PublicKey")

    newSSH := New().FromOpenSSHPrivateKey(prikey)
    assertError(newSSH.Error(), "Test_GenKey_ECDSA_With_Comment-newSSH")

    assertEqual(newSSH.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey_ECDSA_With_Comment-newSSH")
    assertEqual(newSSH.GetComment(), comment, "Test_GenKey_ECDSA_With_Comment-newSSH-comment")

    newSSH2 := New().FromOpenSSHPublicKey(pubkey)
    assertError(newSSH2.Error(), "Test_GenKey_ECDSA_With_Comment-newSSH2")

    assertEqual(newSSH2.GetPublicKey(), obj.GetPublicKey(), "Test_GenKey_ECDSA_With_Comment-newSSH2")
    assertEqual(newSSH2.GetComment(), comment, "Test_GenKey_ECDSA_With_Comment-newSSH2-comment")
}

func Test_OnError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    err := errors.New("test-error")

    testssh := New()
    testssh.Errors = append(testssh.Errors, err)

    testssh = testssh.OnError(func(errs []error) {
        assertEqual(errs, []error{err}, "Test_OnError")
    })

    err2 := testssh.Error().Error()
    assertEqual(err2, err.Error(), "Test_OnError Error")
}

func Test_Get(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    testerr := errors.New("test-error")
    opts := Options{
        PublicKeyType:  KeyTypeRSA,
        Comment:        "test-Comment",
        ParameterSizes: dsa.L1024N160,
        Curve:          elliptic.P256(),
        Bits:           2048,
    }

    newSSH2 := SSH{
        privateKey: privateKey,
        publicKey:  publicKey,
        options:    opts,
        keyData:    []byte("test-keyData"),
        data:       []byte("test-data"),
        parsedData: []byte("test-parsedData"),
        verify: false,
        Errors: []error{testerr},
    }

    assertEqual(newSSH2.GetPrivateKey(), privateKey, "Test_Get-GetPrivateKey")
    assertEqual(newSSH2.GetPrivateKeyType().String(), "RSA", "Test_Get-GetPrivateKeyType")

    openSSHSigner, err := newSSH2.GetOpenSSHSigner()
    assertError(err, "Test_Get-GetOpenSSHSigner")
    assertNotEmpty(openSSHSigner, "Test_Get-GetOpenSSHSigner")

    assertEqual(newSSH2.GetPublicKey(), publicKey, "Test_Get-GetPublicKey")
    assertEqual(newSSH2.GetPublicKeyType().String(), "RSA", "Test_Get-GetPublicKeyType")

    openSSHPublicKey, err := newSSH2.GetOpenSSHPublicKey()
    assertError(err, "Test_Get-GetOpenSSHPublicKey")
    assertNotEmpty(openSSHPublicKey, "Test_Get-GetOpenSSHPublicKey")

    assertEqual(newSSH2.GetOptions(), opts, "Test_Get-GetOptions")
    assertEqual(newSSH2.GetComment(), "test-Comment", "Test_Get-GetComment")
    assertEqual(newSSH2.GetParameterSizes(), dsa.L1024N160, "Test_Get-GetParameterSizes")
    assertEqual(newSSH2.GetCurve(), elliptic.P256(), "Test_Get-GetCurve")
    assertEqual(newSSH2.GetBits(), 2048, "Test_Get-GetBits")

    assertEqual(newSSH2.GetKeyData(), []byte("test-keyData"), "Test_Get-GetKeyData")
    assertEqual(newSSH2.GetData(), []byte("test-data"), "Test_Get-GetData")
    assertEqual(newSSH2.GetParsedData(), []byte("test-parsedData"), "Test_Get-GetParsedData")
    assertEqual(newSSH2.GetVerify(), false, "Test_Get-GetVerify")
    assertEqual(newSSH2.GetErrors(), []error{testerr}, "Test_Get-GetErrors")

    assertEqual(newSSH2.ToKeyBytes(), []byte("test-keyData"), "Test_Get-ToKeyBytes")
    assertEqual(newSSH2.ToKeyString(), "test-keyData", "Test_Get-ToKeyString")

    assertEqual(newSSH2.ToBytes(), []byte("test-parsedData"), "Test_Get-ToBytes")
    assertEqual(newSSH2.ToString(), "test-parsedData", "Test_Get-ToString")
    assertEqual(newSSH2.ToBase64String(), "dGVzdC1wYXJzZWREYXRh", "Test_Get-ToBase64String")
    assertEqual(newSSH2.ToHexString(), "746573742d70617273656444617461", "Test_Get-ToHexString")

    assertEqual(newSSH2.ToVerify(), false, "Test_Get-ToVerify")
    assertEqual(newSSH2.ToVerifyInt(), 0, "Test_Get-ToVerifyInt")
}

func Test_With(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    testerr := errors.New("test-error")
    opts := Options{
        PublicKeyType:  KeyTypeRSA,
        Comment:        "test-Comment",
        ParameterSizes: dsa.L1024N160,
        Curve:          elliptic.P256(),
        Bits:           2048,
    }

    var tmp SSH

    newSSH := SSH{}

    tmp = newSSH.WithPrivateKey(privateKey)
    assertEqual(tmp.privateKey, privateKey, "Test_Get-WithPrivateKey")

    tmp = newSSH.WithPublicKey(publicKey)
    assertEqual(tmp.publicKey, publicKey, "Test_Get-WithPublicKey")

    tmp = newSSH.WithOptions(opts)
    assertEqual(tmp.options, opts, "Test_Get-WithOptions")

    tmp = newSSH.WithPublicKeyType(KeyTypeRSA)
    assertEqual(tmp.options.PublicKeyType, KeyTypeRSA, "Test_Get-WithPublicKeyType")

    tmp = newSSH.SetPublicKeyType("ECDSA")
    assertEqual(tmp.options.PublicKeyType, KeyTypeECDSA, "Test_Get-SetPublicKeyType")

    tmp = newSSH.WithComment("test-Comment")
    assertEqual(tmp.options.Comment, "test-Comment", "Test_Get-WithComment")

    tmp = newSSH.WithParameterSizes(dsa.L1024N160)
    assertEqual(tmp.options.ParameterSizes, dsa.L1024N160, "Test_Get-WithParameterSizes")

    tmp = newSSH.SetParameterSizes("L2048N224")
    assertEqual(tmp.options.ParameterSizes, dsa.L2048N224, "Test_Get-SetParameterSizes")

    tmp = newSSH.WithCurve(elliptic.P384())
    assertEqual(tmp.options.Curve, elliptic.P384(), "Test_Get-WithCurve")

    tmp = newSSH.SetCurve("P521")
    assertEqual(tmp.options.Curve, elliptic.P521(), "Test_Get-SetCurve")

    tmp = newSSH.WithBits(2048)
    assertEqual(tmp.options.Bits, 2048, "Test_Get-WithBits")

    tmp = newSSH.WithKeyData([]byte("test-keyData"))
    assertEqual(tmp.keyData, []byte("test-keyData"), "Test_Get-WithKeyData")

    tmp = newSSH.WithData([]byte("test-data"))
    assertEqual(tmp.data, []byte("test-data"), "Test_Get-WithData")

    tmp = newSSH.WithParsedData([]byte("test-parsedData"))
    assertEqual(tmp.parsedData, []byte("test-parsedData"), "Test_Get-WithParsedData")

    tmp = newSSH.WithVerify(true)
    assertEqual(tmp.verify, true, "Test_Get-WithVerify")

    tmp = newSSH.WithErrors([]error{testerr})
    assertEqual(tmp.Errors, []error{testerr}, "Test_Get-WithErrors")
}

func Test_Error(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    testerr := errors.New("test-error")

    var tmp SSH

    newSSH := SSH{}

    tmp = newSSH.AppendError(testerr)
    assertEqual(tmp.Errors, []error{testerr}, "Test_Error-AppendError")

    err2 := tmp.Error().Error()
    assertEqual(err2, testerr.Error(), "Test_Error-Error")
}
