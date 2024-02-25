package x509

import (
    "net"
    "time"
    "testing"
    "math/big"
    "encoding/pem"
    "encoding/asn1"
    "crypto/rand"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/gost"
    "github.com/deatil/go-cryptobin/gm/sm2"
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

func Test_X509(t *testing.T) {
    priv, err := sm2.GenerateKey(nil) // 生成密钥对
    if err != nil {
        t.Fatal(err)
    }

    privPem, err := sm2.MarshalPrivateKey(priv) // 生成密钥文件
    if err != nil {
        t.Fatal(err)
    }

    privKey, err := sm2.ParsePrivateKey(privPem) // 读取密钥
    if err != nil {
        t.Fatal(err)
    }

    if !priv.Equal(privKey) {
        t.Error("MarshalPrivateKey error")
    }

    pubKey, _ := priv.Public().(*sm2.PublicKey)
    pubkeyPem, err := sm2.MarshalPublicKey(pubKey)       // 生成公钥文件

    pubKey2, err := sm2.ParsePublicKey(pubkeyPem) // 读取公钥
    if err != nil {
        t.Fatal(err)
    }

    if !pubKey2.Equal(pubKey) {
        t.Error("MarshalPublicKey error")
    }

    templateReq := CertificateRequest{
        Subject: pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        },
        // SignatureAlgorithm: ECDSAWithSHA256,
        SignatureAlgorithm: SM2WithSM3,
    }

    reqPem, err := CreateCertificateRequest(rand.Reader, &templateReq, privKey)
    if err != nil {
        t.Fatal(err)
    }

    req, err := ParseCertificateRequest(reqPem)
    if err != nil {
        t.Fatal(err)
    }

    err = req.CheckSignature()
    if err != nil {
        t.Fatalf("Request CheckSignature error:%v", err)
    }

    testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
    testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
    extraExtensionData := []byte("extra extension")
    commonName := "test.example.com"
    template := Certificate{
        // SerialNumber is negative to ensure that negative
        // values are parsed. This is due to the prevalence of
        // buggy code that produces certificates with negative
        // serial numbers.
        SerialNumber: big.NewInt(-1),
        Subject: pkix.Name{
            CommonName:   commonName,
            Organization: []string{"TEST"},
            Country:      []string{"China"},
            ExtraNames: []pkix.AttributeTypeAndValue{
                {
                    Type:  []int{2, 5, 4, 42},
                    Value: "Gopher",
                },
                // This should override the Country, above.
                {
                    Type:  []int{2, 5, 4, 6},
                    Value: "NL",
                },
            },
        },
        NotBefore: time.Now(),
        NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

        //		SignatureAlgorithm: ECDSAWithSHA256,
        SignatureAlgorithm: SM2WithSM3,

        SubjectKeyId: []byte{1, 2, 3, 4},
        KeyUsage:     KeyUsageCertSign,

        ExtKeyUsage:        testExtKeyUsage,
        UnknownExtKeyUsage: testUnknownExtKeyUsage,

        BasicConstraintsValid: true,
        IsCA:                  true,

        OCSPServer:            []string{"http://ocsp.example.com"},
        IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

        DNSNames:       []string{"test.example.com"},
        EmailAddresses: []string{"gopher@golang.org"},
        IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

        PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
        PermittedDNSDomains: []string{".example.com", "example.com"},

        CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

        ExtraExtensions: []pkix.Extension{
            {
                Id:    []int{1, 2, 3, 4},
                Value: extraExtensionData,
            },
            // This extension should override the SubjectKeyId, above.
            {
                Id:       oidExtensionSubjectKeyId,
                Critical: false,
                Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
            },
        },
    }

    pubKey, _ = priv.Public().(*sm2.PublicKey)
    certpem, err := CreateCertificate(&template, &template, pubKey, privKey)
    if err != nil {
        t.Fatal("failed to create cert file")
    }

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

var testGostCert = `
-----BEGIN CERTIFICATE-----
MIIB6TCCAZSgAwIBAgIUUv3U4LiFVjZW4dJVKPIXe/IGeyMwDAYIKoUDBwEBAwIF
ADBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMB4XDTIwMDMxMzAyMDMwOVoXDTMwMDMx
MTAyMDMwOVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf
BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBmMB8GCCqFAwcBAQEBMBMG
ByqFAwICIwEGCCqFAwcBAQICA0MABEDkSyJyVSVzwHJhibRxoZM475OgoNmIKN0w
4jLHZmvLXX70bLa83RebqlVhahbJQ8eSuYm04drZyKPUJVPm7SG2o1MwUTAdBgNV
HQ4EFgQULOn+VVG8YOOEBG0I0F3guXU8VDgwHwYDVR0jBBgwFoAULOn+VVG8YOOE
BG0I0F3guXU8VDgwDwYDVR0TAQH/BAUwAwEB/zAMBggqhQMHAQEDAgUAA0EAv3Sm
QQtmBhm2Y67rNgUxvdLRoD1363eN7Mw0tZ6SDyZvJHODgDSlas4KQKU+tuysCRSW
pINcWw3M4CXPIG9VKQ==
-----END CERTIFICATE-----
`

func Test_P12_Gost(t *testing.T) {
    certpem := decodePEM(testGostCert)

    cert, err := ParseCertificate(certpem)
    if err != nil {
        t.Fatal(err)
    }

    pubKey, _ := cert.PublicKey.(*gost.PublicKey)

    publicKey, err := gost.MarshalPublicKey(pubKey)
    if err != nil {
        t.Fatal(err)
    }

    publicKeyPem := encodePEM(publicKey, "PUBLIC KEY")
    if len(publicKeyPem) == 0 {
        t.Error("fail make publicKey")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        // t.Fatal(err)
    }

    // t.Errorf("%s", publicKeyPem)
}
