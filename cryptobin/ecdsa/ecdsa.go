package ecdsa

import (
    "hash"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

// 数据编码方式
// marshal data type
type EncodingType uint

const (
    EncodingASN1 EncodingType = 1 + iota
    EncodingBytes
)

/**
 * ECDSA
 *
 * @create 2022-4-3
 * @author deatil
 */
type ECDSA struct {
    // PrivateKey
    privateKey *ecdsa.PrivateKey

    // publicKey
    publicKey *ecdsa.PublicKey

    // curve type
    curve elliptic.Curve

    // sign hash type
    signHash HashFunc

    // data encoding type
    encoding EncodingType

    // [PrivateKey/PublicKey]data
    keyData []byte

    // input data
    data []byte

    // parsed data
    parsedData []byte

    // verify data
    verify bool

    // error list
    Errors []error
}

// NewECDSA
func NewECDSA() ECDSA {
    return ECDSA{
        curve:    elliptic.P256(),
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// New ECDSA
func New() ECDSA {
    return NewECDSA()
}

var (
    // default New ECDSA
    defaultECDSA = NewECDSA()
)
