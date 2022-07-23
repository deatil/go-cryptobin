package cryptobin

import (
    "fmt"
    "errors"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/tjfoc/gmsm/sm2"
    sm2X509 "github.com/tjfoc/gmsm/x509"
)

// 证书请求
func (this CA) CreateCSR() CA {
    if this.publicKey == nil || this.privateKey == nil {
        this.Error = errors.New("publicKey or privateKey error.")
        return this
    }

    caBytes, err := x509.CreateCertificate(rand.Reader, this.csr, this.csr, this.publicKey, this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    caBlock := &pem.Block{
        Type: "CERTIFICATE",
        Bytes: caBytes,
    }

    this.keyData = pem.EncodeToMemory(caBlock)

    return this
}

// 自签名证书
func (this CA) CreateCert(ca *x509.Certificate) CA {
    if this.publicKey == nil || this.privateKey == nil {
        this.Error = errors.New("publicKey or privateKey error.")
        return this
    }

    caBytes, err := x509.CreateCertificate(rand.Reader, this.csr, ca, this.publicKey, this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    caBlock := &pem.Block{
        Type: "CERTIFICATE",
        Bytes: caBytes,
    }

    this.keyData = pem.EncodeToMemory(caBlock)

    return this
}

// 私钥
func (this CA) CreatePrivateKey() CA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")

        return this
    }

    var x509PrivateKey []byte

    switch privateKey := this.privateKey.(type) {
        case *rsa.PrivateKey:
            x509PrivateKey = x509.MarshalPKCS1PrivateKey(privateKey)

        case *ecdsa.PrivateKey:
            var err error
            x509PrivateKey, err = x509.MarshalECPrivateKey(privateKey)
            if err != nil {
                this.Error = err
                return this
            }

        case ed25519.PrivateKey:
            var err error
            x509PrivateKey, err = x509.MarshalPKCS8PrivateKey(privateKey)
            if err != nil {
                this.Error = err
                return this
            }

        case *sm2.PrivateKey:
            this.keyData, this.Error = sm2X509.WritePrivateKeyToPem(privateKey, nil)
            return this

        default:
            this.Error = fmt.Errorf("x509: unsupported private key type: %T", privateKey)
            return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}
