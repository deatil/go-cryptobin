package dsa

import (
    "errors"
    "encoding/pem"
)

// Make PublicKey
func (this DSA) MakePublicKey() DSA {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// Make Key Der data
func (this DSA) MakeKeyDer() DSA {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/dsa: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
