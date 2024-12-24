package ecsdsa

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/ecsdsa"
)

type (
    // 配置
    Opts       = pkcs8.Opts
    // PBKDF2 配置
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = pkcs8.ScryptOpts
)

var (
    // 获取 Cipher 类型
    GetCipherFromName = pkcs8.GetCipherFromName
    // 获取 hash 类型
    GetHashFromName   = pkcs8.GetHashFromName
)

// 生成私钥 pem 数据, PKCS1 别名
// 使用:
// obj := New().WithCurve("P521").GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this ECSDSA) CreatePrivateKey() ECSDSA {
    return this.CreatePKCS1PrivateKey()
}

// 生成私钥带密码 pem 数据, PKCS1 别名
// CreatePrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this ECSDSA) CreatePrivateKeyWithPassword(password string, opts ...string) ECSDSA {
    return this.CreatePKCS1PrivateKeyWithPassword(password, opts...)
}

// ====================

// 生成私钥 pem 数据
func (this ECSDSA) CreatePKCS1PrivateKey() ECSDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := ecsdsa.MarshalECPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "ECSDSA PRIVATE KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成私钥带密码 pem 数据
func (this ECSDSA) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) ECSDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 加密方式
    cipher := pkcs1.GetPEMCipher(opt)
    if cipher == nil {
        err := errors.New("PEMCipher not exists.")
        return this.AppendError(err)
    }

    // 生成私钥
    publicKeyBytes, err := ecsdsa.MarshalECPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs1.EncryptPEMBlock(
        rand.Reader,
        "ECSDSA PRIVATE KEY",
        publicKeyBytes,
        []byte(password),
        cipher,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// ====================

// 生成 PKCS8 私钥 pem 数据
func (this ECSDSA) CreatePKCS8PrivateKey() ECSDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := ecsdsa.MarshalPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this ECSDSA) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) ECSDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    publicKeyBytes, err := ecsdsa.MarshalPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        publicKeyBytes,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// ====================

// 生成公钥 pem 数据
func (this ECSDSA) CreatePublicKey() ECSDSA {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := ecsdsa.MarshalPublicKey(this.publicKey)
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