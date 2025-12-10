package ed448

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pubkey/ed448"
)

// Make PublicKey
func (this ED448) MakePublicKey() ED448 {
    this.publicKey = ed448.PublicKey{}

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ed448: privateKey empty.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = this.privateKey.Public().(ed448.PublicKey)

    return this
}

// Make Key Der data
func (this ED448) MakeKeyDer() ED448 {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/ed448: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
