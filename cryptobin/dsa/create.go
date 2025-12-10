package dsa

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/dsa"
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
// dsa := New().GenerateKey("L2048N256")
// priKey := dsa.CreatePrivateKey().ToKeyString()
func (this DSA) CreatePrivateKey() DSA {
    return this.CreatePKCS1PrivateKey()
}

// Create PrivateKey PEM data with password
// CreatePrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this DSA) CreatePrivateKeyWithPassword(password string, opts ...string) DSA {
    return this.CreatePKCS1PrivateKeyWithPassword(password, opts...)
}

// Create PublicKey PEM data
func (this DSA) CreatePublicKey() DSA {
    return this.CreatePKCS1PublicKey()
}

// ==========

// Create PKCS1 PrivateKey PEM data
func (this DSA) CreatePKCS1PrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := dsa.MarshalPKCS1PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "DSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PKCS1 PrivateKey PEM data with password
// CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this DSA) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 加密方式
    cipher := pkcs1.GetPEMCipher(opt)
    if cipher == nil {
        err := errors.New("go-cryptobin/dsa: PEMCipher not exists.")
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := dsa.MarshalPKCS1PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs1.EncryptPEMBlock(
        rand.Reader,
        "DSA PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        cipher,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// Create PKCS1 PublicKey PEM data
func (this DSA) CreatePKCS1PublicKey() DSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/dsa: publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := dsa.MarshalPKCS1PublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "DSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// ==========

// Create PKCS8 PrivateKey PEM data
func (this DSA) CreatePKCS8PrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := dsa.MarshalPKCS8PrivateKey(this.privateKey)
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
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this DSA) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := dsa.MarshalPKCS8PrivateKey(this.privateKey)
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

// Create PKCS8 PublicKey PEM data
func (this DSA) CreatePKCS8PublicKey() DSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/dsa: publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := dsa.MarshalPKCS8PublicKey(this.publicKey)
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

// ====================

// Create PrivateKey XML data
func (this DSA) CreateXMLPrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    xmlPrivateKey, err := dsa.MarshalXMLPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = xmlPrivateKey

    return this
}

// Create PublicKey XML data
func (this DSA) CreateXMLPublicKey() DSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/dsa: publicKey empty.")
        return this.AppendError(err)
    }

    xmlPublicKey, err := dsa.MarshalXMLPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = xmlPublicKey

    return this
}

