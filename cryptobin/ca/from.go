package ca

import (
    "crypto/x509"
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
