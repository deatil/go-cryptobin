package ecdsa

import(
    "errors"
    "encoding/pem"
)

// Make PublicKey
func (this ECDSA) MakePublicKey() ECDSA {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdsa: privateKey empty.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// Make Key Der data
func (this ECDSA) MakeKeyDer() ECDSA {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/ecdsa: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
