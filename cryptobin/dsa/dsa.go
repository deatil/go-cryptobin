package dsa

import (
    "hash"
    "crypto/dsa"
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
 * DSA
 *
 * @create 2022-7-25
 * @author deatil
 */
type DSA struct {
    // PrivateKey
    privateKey *dsa.PrivateKey

    // PublicKey
    publicKey *dsa.PublicKey

    // [PrivateKey/PublicKey]data
    keyData []byte

    // input data
    data []byte

    // parsed data
    parsedData []byte

    // sign hash type
    signHash HashFunc

    // encoding type
    encoding EncodingType

    // verify data
    verify bool

    // error list
    Errors []error
}

// NewDSA
func NewDSA() DSA {
    return DSA{
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// New DSA
func New() DSA {
    return NewDSA()
}

var (
    // default New DSA
    defaultDSA = NewDSA()
)
