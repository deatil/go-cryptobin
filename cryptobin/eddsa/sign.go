package eddsa

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ed25519"
)

// 私钥签名
func (this EdDSA) Sign() EdDSA {
    if this.privateKey == nil {
        err := errors.New("EdDSA: privateKey error.")
        return this.AppendError(err)
    }

    hashed := this.dataHash(this.data, this.options)

    sig, err := this.privateKey.Sign(rand.Reader, hashed, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this
}

// 公钥验证
func (this EdDSA) Verify(data []byte) EdDSA {
    if this.publicKey == nil {
        err := errors.New("EdDSA: publicKey error.")
        return this.AppendError(err)
    }

    hashed := this.dataHash(data, this.options)

    err := ed25519.VerifyWithOptions(this.publicKey, hashed, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}

// 判断是否需要做 hash
func (this EdDSA) dataHash(data []byte, opts *Options) []byte {
    hash := opts.HashFunc()

    if hash == crypto.SHA512 {
        h := hash.New()
        h.Write(data)

        return h.Sum(nil)
    }

    return data
}
