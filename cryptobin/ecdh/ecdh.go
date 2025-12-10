package ecdh

import (
    "crypto/ecdh"
)

/**
 * ecdh
 *
 * @create 2022-8-7
 * @author deatil
 */
type ECDH struct {
    // PrivateKey
    privateKey *ecdh.PrivateKey

    // publicKey
    publicKey *ecdh.PublicKey

    // curve type
    curve ecdh.Curve

    // [PrivateKey/PublicKey]data
    keyData []byte

    // secret data
    secretData []byte

    // error list
    Errors []error
}

// NewECDH
func NewECDH() ECDH {
    return ECDH{
        curve:  ecdh.P256(),
        Errors: make([]error, 0),
    }
}

// New ECDH
func New() ECDH {
    return NewECDH()
}

var (
    // default New ECDH
    defaultECDH = NewECDH()
)
