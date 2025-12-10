package ed521

import (
    "crypto"

    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

type (
    Options = ed521.Options
)

const (
    SchemeED521   = ed521.ED521
    SchemeED521Ph = ed521.ED521Ph
)

/**
 * ED521
 *
 * @create 2025-12-2
 * @author deatil
 */
type ED521 struct {
    // PrivateKey
    privateKey *ed521.PrivateKey

    // PublicKey
    publicKey *ed521.PublicKey

    // Options
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

// NewED521
func NewED521() ED521 {
    return ED521{
        options: &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED521,
        },
        verify:  false,
        Errors:  make([]error, 0),
    }
}

// NewED521
func New() ED521 {
    return NewED521()
}

var (
    // default New ED521
    defaultED521 = NewED521()
)
