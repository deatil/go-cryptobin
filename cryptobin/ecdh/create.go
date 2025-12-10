package ecdh

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/ecdh"
    ecdh_key "github.com/deatil/go-cryptobin/ecdh/key"
)

type (
    // Options
    Opts       = pkcs8.Opts
    // PBKDF2 Options
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt Options
    ScryptOpts = pkcs8.ScryptOpts
)

var (
    // Get cipher from name
    GetCipherFromName = pkcs8.GetCipherFromName
    // Get hash from name
    GetHashFromName   = pkcs8.GetHashFromName
)

// Create PKCS8 PrivateKey PEM data
// example:
// obj := New().SetCurve("P256").GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this ECDH) CreatePrivateKey() ECDH {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdh: privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PKCS8 PrivateKey PEM data with password
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this ECDH) CreatePrivateKeyWithPassword(password string, opts ...any) ECDH {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdh: privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PublicKey PEM data
func (this ECDH) CreatePublicKey() ECDH {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ecdh: publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := x509.MarshalPKIXPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// =======================

// 生成私钥 pem 数据, 库自使用的 asn1 格式
// Create PKCS8 PrivateKey PEM data and use the pkg asn1 encode
func (this ECDH) CreateECDHPrivateKey() ECDH {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdh: privateKey empty.")
        return this.AppendError(err)
    }

    privateKey, err := ecdh.FromPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateKeyBytes, err := ecdh_key.MarshalPrivateKey(privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据, 库自使用的 asn1 格式
// Create PKCS8 PrivateKey PEM data with password
// and use the pkg asn1 encode
func (this ECDH) CreateECDHPrivateKeyWithPassword(password string, opts ...any) ECDH {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdh: privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    privateKey, err := ecdh.FromPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := ecdh_key.MarshalPrivateKey(privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PublicKey PEM data and use the pkg asn1 encode
func (this ECDH) CreateECDHPublicKey() ECDH {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ecdh: publicKey empty.")
        return this.AppendError(err)
    }

    publicKey, err := ecdh.FromPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicKeyBytes, err := ecdh_key.MarshalPublicKey(publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// =======================

// Create SecretKey from PrivateKey and PublicKey
func (this ECDH) CreateSecretKey() ECDH {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdh: privateKey empty.")
        return this.AppendError(err)
    }

    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ecdh: publicKey empty.")
        return this.AppendError(err)
    }

    secretKey, err := this.privateKey.ECDH(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.secretData = secretKey

    return this
}
