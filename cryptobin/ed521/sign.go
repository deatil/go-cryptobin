package ed521

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

// 私钥签名
func (this ED521) Sign() ED521 {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ed521: privateKey empty.")
        return this.AppendError(err)
    }

    sig, err := this.privateKey.Sign(rand.Reader, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this
}

// 公钥验证
func (this ED521) Verify(data []byte) ED521 {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ed521: publicKey empty.")
        return this.AppendError(err)
    }

    err := ed521.VerifyWithOptions(this.publicKey, data, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
