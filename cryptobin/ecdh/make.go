package ecdh

import (
    "errors"
    "encoding/pem"
)

// Make PublicKey
func (this ECDH) MakePublicKey() ECDH {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdh: privateKey empty.")
        return this.AppendError(err)
    }

    this.publicKey = this.privateKey.PublicKey()

    return this
}

// Make Key Der data
func (this ECDH) MakeKeyDer() ECDH {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/ecdh: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
