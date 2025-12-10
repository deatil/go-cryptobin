package ed448

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/ed448"
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

// Create PrivateKey PEM data
func (this ED448) CreatePrivateKey() ED448 {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ed448: privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := ed448.MarshalPrivateKey(this.privateKey)
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

// Create PrivateKey PEM data with password
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this ED448) CreatePrivateKeyWithPassword(password string, opts ...any) ED448 {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ed448: privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := ed448.MarshalPrivateKey(this.privateKey)
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
func (this ED448) CreatePublicKey() ED448 {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ed448: publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := ed448.MarshalPublicKey(this.publicKey)
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
