package rsa

import (
    "errors"
    "crypto/rand"
    "crypto/rsa"
    
    "github.com/deatil/go-cryptobin/tool"
)

// 私钥签名
// 常用为: PS256[SHA256] | PS384[SHA384] | PS512[SHA512]
func (this Rsa) PSSSign(opts ...rsa.PSSOptions) Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    newHash := tool.NewHash()

    hash := newHash.GetCryptoHash(this.signHash)
    hashed := newHash.DataCryptoHash(this.signHash, this.data)

    options := rsa.PSSOptions{
        SaltLength: rsa.PSSSaltLengthEqualsHash,
    }

    if len(opts) > 0 {
        options = opts[0]
    }

    this.paredData, this.Error = rsa.SignPSS(rand.Reader, this.privateKey, hash, hashed, &options)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Rsa) PSSVery(data []byte, opts ...rsa.PSSOptions) Rsa {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    newHash := tool.NewHash()

    hash := newHash.GetCryptoHash(this.signHash)
    hashed := newHash.DataCryptoHash(this.signHash, data)

    options := rsa.PSSOptions{
        SaltLength: rsa.PSSSaltLengthAuto,
    }

    if len(opts) > 0 {
        options = opts[0]
    }

    err := rsa.VerifyPSS(this.publicKey, hash, hashed, this.data, &options)
    if err != nil {
        this.veryed = false
        this.Error = err

        return this
    }

    this.veryed = true

    return this
}
