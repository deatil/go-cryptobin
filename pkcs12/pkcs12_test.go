package pkcs12

import (
    "testing"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

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

func Test_EncodeSecret(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    secretKey := []byte("test-password")
    password := "passpass word"

    pfxData, err := EncodeSecret(rand.Reader, secretKey, password, DefaultOpts)
    assertError(err, "EncodeSecret")

    secretKeys, err := DecodeSecret(pfxData, password)
    assertError(err, "DecodeSecret")

    if len(secretKeys) != 1 {
        t.Error("DecodeSecret Error")
    }

    oldpass := sha1.Sum(secretKey)
    newpass := secretKeys[0].Attributes()

    assertEqual(newpass["localKeyId"], hex.EncodeToString(oldpass[:]), "secretKey")

    assertEqual(secretKeys[0].Key(), secretKey, "EncodeSecret")
}

func Test_EncodeSecret_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    secretKey := []byte("test-password")
    password := ""

    pfxData, err := EncodeSecret(rand.Reader, secretKey, password, PasswordlessOpts)
    assertError(err, "EncodeSecret-Passwordless")

    secretKeys, err := DecodeSecret(pfxData, password)
    assertError(err, "DecodeSecret-Passwordless")

    if len(secretKeys) != 1 {
        t.Error("DecodeSecret Error")
    }

    oldpass := sha1.Sum(secretKey)
    newpass := secretKeys[0].Attributes()

    assertEqual(newpass["localKeyId"], hex.EncodeToString(oldpass[:]), "secretKey")

    assertEqual(secretKeys[0].Key(), secretKey, "EncodeSecret-Passwordless")
}

var caCert = `
-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIQAJHs2CT5Pzi/46ZOhdGusTANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApnaXRodWIuY29tMB4XDTIyMDkwOTAyNDkyMloXDTMyMDkwNjAy
NDkyMlowFTETMBEGA1UEAwwKZ2l0aHViLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKsLdJmjBih0/+lhbT5RlqpDef0/gO+LeQVpE6LDLw45uYPx
vknOFbHWrRuuu//jroWcOYNsrLX/ci57vyFH6mM06/MxrUu6tFSXxbYl48quipcb
KgFoEuNLwn1fuc1lMNq2t94cC3tHgfWDjNHB4FA7zHYYWfX5t4pPktKaPP8Uo726
ntC4VX+RoMbX6diul5fO8F7tXwtpOaaTmzti2XLBUbWHQGpudfjE6losyrsWZ7SS
w8FuKYcjoXiI1IOhq+9sAqmuGPJwJWFV/qEDzVonDCriTdE3u4JR1BmcHgguBnDp
Xf1/01wOVRce6ljtrrtey4qxieqGKu6cu9WEhm8CAwEAAaOBuDCBtTAVBgNVHREE
DjAMggpnaXRodWIuY29tMB0GA1UdDgQWBBSVT+T++EKY2x6eM2EVG8GuMTL5OjAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zA7BgNVHSUENDAyBggrBgEF
BQcDAgYIKwYBBQUHAwEGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwHwYD
VR0jBBgwFoAUlU/k/vhCmNsenjNhFRvBrjEy+TowDQYJKoZIhvcNAQELBQADggEB
AHEaGp+1WlgVWZh+Khn0cnqzmWhixLUlpaOzHIjfob3+DfdVVuShbwhIOk7+rtv8
nLGZAFKvC9zcR4JT1GEARSu5UJCwbIanaTAxXSZvpfQnuSpvf2sazumdX1BoOdOP
a8pQ/QWkgdNXO19Co/XKYaHlZsFSAt2UNTy1WEANxcw/JLdKKENmFvhO9r6dWp/8
a1eWkjUETqAnYHnCvOl7Y3cqb6bKpRF89g923VPjr/kzLHcHzIpKVxpDQz3sLKN4
abSw3VJ3HP+iQ27b65yP+E7pr1PE8hEDhApFliWvKLW7uGx9v7M7ukuSt37acKy1
M/XkkXfOEjWtKqd5FepSAIU=
-----END CERTIFICATE-----
`
var certificate = `
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIQAKUxXiUjuCQwQhAxfRz2UzANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApnaXRodWIuY29tMB4XDTIyMDkwOTAyNTY0OFoXDTMyMDkwNzAy
NTY0OFowFTETMBEGA1UEAwwKZ2l0aHViLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAIM0DBC9QSpFvIzY2muwz2Oms+2EAAj3nyLxvZ1vDGcA3NXy
Zoc6sKt4n9x2wH4m1UlHPpm8jmlgixVx1aLO6n1RapFFuq8T72rJQnx05+Wfo9lh
pE65o+zGibt4Hgw6WcChfaSpyL/C490ih6pbGQVvvV0IkalRzm1AzTbXriSxkiv/
MovHvdkmN8DsgFnowK2MRBAZPqT8p31ch+CyehRKuQvyGhQoyKXyI5YnLJP6lYh9
zcHr4VfVByIho23FuNW8xmvJ+foL90wXu17E3CWquO4IahJq4zuwsVSI3s5v9g8Z
PXD9/F0mEtifEo4nztDwdFHWbFkQmy7ieKwsRu0CAwEAAaOBlzCBlDAVBgNVHREE
DjAMggpnaXRodWIuY29tMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFK6IfWox0KiL
HjqgTBHo9YscTCnHMA4GA1UdDwEB/wQEAwIEsDAdBgNVHSUEFjAUBggrBgEFBQcD
AgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUlU/k/vhCmNsenjNhFRvBrjEy+TowDQYJ
KoZIhvcNAQELBQADggEBAElshxG3pzbDtwNJXt2F+RBpVlBN5tQtFyhR4ws/ORRO
mISfu+FRBo5lQCsJHZh4eP3q6ssgGyasRVIyv9yshG/MTcbjZnuivZw2t0F/EkTz
KHcj/PwprC5Qcs6Hq71344LsW/GdXnqA4KpzJhyc3BGUZS676AVCskXYfGml8dN9
YvX7ntOZVGzfv+gK7G/EBM7YCmGZFpxNi6OFMOzNljdJIJmxON+9+QBvfCD4nN7K
dGW3DQGZNm7K60G2Z5FTL/7x7EQ4ZFX6Ls3XVoJ3qqXh7aHybCQtkAvAMUemug7L
yi/7J8xpalLI6rWhqBtxXFFL7l363cilCRx7vxSd578=
-----END CERTIFICATE-----
`
var privateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrC3SZowYodP/p
YW0+UZaqQ3n9P4Dvi3kFaROiwy8OObmD8b5JzhWx1q0brrv/466FnDmDbKy1/3Iu
e78hR+pjNOvzMa1LurRUl8W2JePKroqXGyoBaBLjS8J9X7nNZTDatrfeHAt7R4H1
g4zRweBQO8x2GFn1+beKT5LSmjz/FKO9up7QuFV/kaDG1+nYrpeXzvBe7V8LaTmm
k5s7YtlywVG1h0BqbnX4xOpaLMq7Fme0ksPBbimHI6F4iNSDoavvbAKprhjycCVh
Vf6hA81aJwwq4k3RN7uCUdQZnB4ILgZw6V39f9NcDlUXHupY7a67XsuKsYnqhiru
nLvVhIZvAgMBAAECggEAS6eD+eaxNRjXDqewtbVJwmKZJQo/IfUbYOjCriXN/OlM
ZI97HtMAJopxRALMFdljmqZoi/h4BgIIQ4YpmnNgOWQxjv5ki8/3rkj5QuFMeZwt
Ibv6nuelHxMl4eWC3dYJv1u9RQk7jNoqoej/UtIBwQtKGtwXgmRjKdKbevqMyzfh
AR3q12HxyznliXYjlTcrHki+x9MFQuc1wbu+8c9YeTr69SpGkgAlGZhDsuvEZ6fO
5vd4nhAAOcHvHJbO2DC1LwkR2Qv6JJlJbw4XO7FJUwgB0P1+J1bAdudaJtfqz4RX
NXkxWHWmCEg4+aoeI52/46sLw2MmfGv1Mt0zzRP2lQKBgQDcJWg61dD3IbUg+LN3
WGNmIyhGBx9vZI4dQE567YIPvvTPKBOFosNLUUAOY04SiUSaZtAxHsLVRCyfKU3b
1kSAd7BWKgy2//WNsLBH8gJ1gQYnfxKzVWGmazS3WNsXp4f4UVQRc9PYWAvVabkk
WCG+5EWkDWFEU2OJK8cyRVxkGwKBgQDG5tsOhT2YxqYGXtR3Im50OK7DYj/TNN+w
SBs7n6ZZGxdb2QHKEI1dO+siDHMmd+4aBif/BdcgOql2MwGE9H71tpn/D+2WRuT1
Ick8P0HNp/hT3OE+LfP6d3hiX53tdvo9CZFBe+P1WLWbHzPVao7WOtu1381RD8yR
ovMCu1TEPQKBgHp2kLHSCcnARYtO7j7gu4Kw4hF6muETlf7tq/q0LtrlhjfK+nkn
nu5CB5k5Ys/q7m/Z68y3aPjMUOpFRtuZKUgxzLVR9PrEDmxAsv+CwB1vpeXIybVb
NNQn5Q5tbouNFZVsYJDI1zsNV5/jjSuLn1IamCb3jnk8zi0bXlc3wHqrAoGBAJg0
uvb+oSdTBGOll8Le91U6twnPGnZeZLq6QxS6VAql/5cKliLxzavGGWYBzvBmIC+L
/HlcF8aS/XD1ETmT+7++D1Qu9SnlcHnhc+QFqC5fVlmekkMJ2UUWvWnSL8EzJcUl
mCFbVBNA4iAlnX24QDvR6KXh8HUSuQHNh1bU0cYlAoGAMcHuW3f/Tm3IXCG9Ssmp
ZmZrnVaXRRjGWpEVAq6SOuDxfSWoM1VdBHZJYiaC3vzStc8dFdzi8MHPlSpGEbiN
s7GpWms8Umk85u0QRJ48S1MRPQ0VMXWKjzYRyjBtmUXaRRKVhm5RhLJ+1O1AzcVV
i3iRrMnLQscEpZzE4P+guWM=
-----END PRIVATE KEY-----
`

func Test_EncodeChain(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "EncodeChain-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeChain-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "EncodeChain-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("EncodeChain rsa Error")
    }

    password := "password-testkjjj"

    pfxData, err := EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        CertKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "EncodeChain-pfxData")

    assertNotEmpty(pfxData, "EncodeChain-pfxData")

    privateKey2, certificate2, caCerts2, err := DecodeChain(pfxData, password)
    assertError(err, "DecodeChain-pfxData")

    assertEqual(privateKey2, privateKey, "EncodeChain-privateKey2")
    assertEqual(certificate2, certificates[0], "EncodeChain-certificate2")
    assertEqual(caCerts2, caCerts, "EncodeChain-caCerts2")
}

func Test_EncodeChain_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "EncodeChain-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeChain-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "EncodeChain-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("EncodeChain rsa Error")
    }

    password := ""

    pfxData, err := EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, password, PasswordlessOpts)
    assertError(err, "EncodeChain-pfxData")

    assertNotEmpty(pfxData, "EncodeChain-pfxData")

    privateKey2, certificate2, caCerts2, err := DecodeChain(pfxData, password)
    assertError(err, "DecodeChain-pfxData")

    assertEqual(privateKey2, privateKey, "EncodeChain-privateKey2")
    assertEqual(certificate2, certificates[0], "EncodeChain-certificate2")
    assertEqual(caCerts2, caCerts, "EncodeChain-caCerts2")
}

func Test_EncodeTrustStore(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStore-certificates")

    password := "password-testkjjj"

    pfxData, err := EncodeTrustStore(rand.Reader, certificates, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        CertKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "EncodeTrustStore-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStore-pfxData")

    certs, err := DecodeTrustStore(pfxData, password)
    assertError(err, "DecodeTrustStore-pfxData")

    assertEqual(certs, certificates, "DecodeTrustStore-privateKey2")
}

func Test_EncodeTrustStore_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStore-certificates")

    password := ""

    pfxData, err := EncodeTrustStore(rand.Reader, certificates, password, PasswordlessOpts)
    assertError(err, "EncodeTrustStore-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStore-pfxData")

    certs, err := DecodeTrustStore(pfxData, password)
    assertError(err, "DecodeTrustStore-pfxData")

    assertEqual(certs, certificates, "DecodeTrustStore-privateKey2")
}

func Test_Encode(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "Encode-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "Encode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("Encode rsa Error")
    }

    password := "password-testkjjj"

    pfxData, err := Encode(rand.Reader, privateKey, certificates[0], password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        CertKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "Encode-pfxData")

    assertNotEmpty(pfxData, "Encode-pfxData")

    privateKey2, certificate2, err := Decode(pfxData, password)
    assertError(err, "Decode-pfxData")

    assertEqual(privateKey2, privateKey, "Decode-privateKey2")
    assertEqual(certificate2, certificates[0], "Decode-certificate2")
}

func Test_Encode_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "Encode-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "Encode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("Encode rsa Error")
    }

    password := ""

    pfxData, err := Encode(rand.Reader, privateKey, certificates[0], password, PasswordlessOpts)
    assertError(err, "Encode-pfxData")

    assertNotEmpty(pfxData, "Encode-pfxData")

    privateKey2, certificate2, err := Decode(pfxData, password)
    assertError(err, "Decode-pfxData")

    assertEqual(privateKey2, privateKey, "Decode-privateKey2")
    assertEqual(certificate2, certificates[0], "Decode-certificate2")
}

func Test_EncodeTrustStoreEntries(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStoreEntries-certificates")

    password := "password-testkjjj"

    entries := make([]TrustStoreEntry, 0)
    entries = append(entries, TrustStoreEntry{
        certificates[0],
        "FriendlyName-Test",
    })

    pfxData, err := EncodeTrustStoreEntries(rand.Reader, entries, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        CertKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "EncodeTrustStoreEntries-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStoreEntries-pfxData")

    certificate2, err := DecodeTrustStoreEntries(pfxData, password)
    assertError(err, "EncodeTrustStoreEntries-pfxData2")

    attrs := certificate2[0].Attributes()

    assertEqual(certificate2[0].Cert(), certificates[0], "EncodeTrustStoreEntries-certificate2")

    assertEqual(attrs["friendlyName"], "FriendlyName-Test", "EncodeTrustStoreEntries-friendlyName")
    assertEqual(attrs["javaTrustStore"], "2.5.29.37.0", "EncodeTrustStoreEntries-friendlyName")
}

func Test_EncodeTrustStoreEntries_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStoreEntries-certificates")

    password := ""

    entries := make([]TrustStoreEntry, 0)
    entries = append(entries, TrustStoreEntry{
        certificates[0],
        "FriendlyName-Test",
    })

    pfxData, err := EncodeTrustStoreEntries(rand.Reader, entries, password, PasswordlessOpts)
    assertError(err, "EncodeTrustStoreEntries-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStoreEntries-pfxData")

    certificate2, err := DecodeTrustStoreEntries(pfxData, password)
    assertError(err, "EncodeTrustStoreEntries-pfxData2")

    attrs := certificate2[0].Attributes()

    assertEqual(certificate2[0].Cert(), certificates[0], "EncodeTrustStoreEntries-certificate2")

    assertEqual(attrs["friendlyName"], "FriendlyName-Test", "EncodeTrustStoreEntries-friendlyName")
    assertEqual(attrs["javaTrustStore"], "2.5.29.37.0", "EncodeTrustStoreEntries-friendlyName")
}


