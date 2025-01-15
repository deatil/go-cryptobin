package ca

import (
    "crypto"
)

// 设置 cert
// 可用 [*x509.Certificate | *sm2X509.Certificate]
func (this CA) WithCert(cert any) CA {
    this.cert = cert

    return this
}

// 设置 certRequest
// 可用 [*x509.CertificateRequest | *sm2X509.CertificateRequest]
func (this CA) WithCertRequest(cert any) CA {
    this.certRequest = cert

    return this
}

// 设置 PrivateKey
func (this CA) WithPrivateKey(key crypto.PrivateKey) CA {
    this.privateKey = key

    return this
}

// 设置 publicKey
func (this CA) WithPublicKey(key crypto.PublicKey) CA {
    this.publicKey = key

    return this
}

// 设置 keyData
func (this CA) WithKeyData(data []byte) CA {
    this.keyData = data

    return this
}

// 设置错误
func (this CA) WithErrors(errs []error) CA {
    this.Errors = errs

    return this
}
