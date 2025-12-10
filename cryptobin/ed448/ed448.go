package ed448

import (
    "crypto"

    "github.com/deatil/go-cryptobin/pubkey/ed448"
)

type (
    Options = ed448.Options
)

const (
    SchemeED448   = ed448.ED448
    SchemeED448Ph = ed448.ED448Ph
)

/**
 * ED448
 *
 * @create 2023-10-25
 * @author deatil
 */
type ED448 struct {
    // PrivateKey
    privateKey ed448.PrivateKey

    // PublicKey
    publicKey ed448.PublicKey

    // options
    options *Options

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

// NewED448
func NewED448() ED448 {
    return ED448{
        options: &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED448,
        },
        verify:  false,
        Errors:  make([]error, 0),
    }
}

// New ED448
func New() ED448 {
    return NewED448()
}

var (
    // default New ED448
    defaultED448 = NewED448()
)
