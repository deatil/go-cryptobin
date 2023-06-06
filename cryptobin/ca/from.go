package ca

import (
    "errors"
    "crypto/x509"
    "crypto/ecdsa"

    "github.com/tjfoc/gmsm/sm2"
    sm2_pkcs12 "github.com/tjfoc/gmsm/pkcs12"

    cryptobin_pkcs12 "github.com/deatil/go-cryptobin/pkcs12"
)

// 证书
func (this CA) FromCert(cert *x509.Certificate) CA {
    this.cert = cert

    return this
}

// 解析证书导入
func (this CA) FromCertificateDer(der []byte) CA {
    cert, err := x509.ParseCertificate(der)
    if err != nil {
        return this.AppendError(err)
    }

    this.cert = cert

    return this
}

// 证书请求
func (this CA) FromCertRequest(cert *x509.CertificateRequest) CA {
    this.certRequest = cert

    return this
}

// 解析证书导入
func (this CA) FromCertificateRequestDer(asn1Data []byte) CA {
    certRequest, err := x509.ParseCertificateRequest(asn1Data)
    if err != nil {
        return this.AppendError(err)
    }

    this.certRequest = certRequest

    return this
}

// 私钥
// 可用 [*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey | *sm2.PrivateKey]
func (this CA) FromPrivateKey(key any) CA {
    this.privateKey = key

    return this
}

// 公钥
// 可用 [*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey | *sm2.PublicKey]
func (this CA) FromPublicKey(key any) CA {
    this.publicKey = key

    return this
}

// =======================

// pkcs12
func (this CA) FromSM2PKCS12Cert(pfxData []byte, password string) CA {
    pv, certs, err := sm2_pkcs12.DecodeAll(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    switch k := pv.(type) {
        case *ecdsa.PrivateKey:
            switch k.Curve {
                case sm2.P256Sm2():
                    sm2pub := &sm2.PublicKey{
                        Curve: k.Curve,
                        X:     k.X,
                        Y:     k.Y,
                    }

                    sm2Pri := &sm2.PrivateKey{
                        PublicKey: *sm2pub,
                        D:         k.D,
                    }

                    if !k.IsOnCurve(k.X, k.Y) {
                        err := errors.New("error while validating SM2 private key: %v")
                        return this.AppendError(err)
                    }

                    this.privateKey = sm2Pri
                    this.cert = certs[0]

                    return this
                default:
                    // other
            }
        default:
            // other
    }

    err = errors.New("unexpected type for p12 private key")

    return this.AppendError(err)
}

// pkcs12
func (this CA) FromPKCS12Cert(pfxData []byte, password string) CA {
    privateKey, cert, err := cryptobin_pkcs12.Decode(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.cert = cert

    return this
}
