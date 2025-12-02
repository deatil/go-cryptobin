package ed521

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

// 生成公钥
func (this ED521) MakePublicKey() ED521 {
    this.publicKey = &ed521.PublicKey{}

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ed521: privateKey empty.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this ED521) MakeKeyDer() ED521 {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/ed521: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
