package ecdsa

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/ecies"
)

// publicKey Encrypt data
// ECDSA 核心为对称加密
func (this ECDSA) Encrypt() ECDSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ecdsa: publicKey empty.")
        return this.AppendError(err)
    }

    publicKey := ecies.ImportECDSAPublicKey(this.publicKey)

    parsedData, err := ecies.Encrypt(rand.Reader, publicKey, this.data, nil, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// privateKey Decrypt data
// ECDSA 核心为对称加密
func (this ECDSA) Decrypt() ECDSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecdsa: privateKey empty.")
        return this.AppendError(err)
    }

    privateKey := ecies.ImportECDSAPrivateKey(this.privateKey)

    parsedData, err := ecies.Decrypt(privateKey, this.data, nil, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
