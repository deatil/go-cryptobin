package ed521

import (
    "crypto"
    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

// With PrivateKey
func (this ED521) WithPrivateKey(data *ed521.PrivateKey) ED521 {
    this.privateKey = data

    return this
}

// With PublicKey
func (this ED521) WithPublicKey(data *ed521.PublicKey) ED521 {
    this.publicKey = data

    return this
}

// With options
func (this ED521) WithOptions(op *Options) ED521 {
    this.options = op

    return this
}

// With options
// can use types [ED521Ph | ED521]
func (this ED521) SetOptions(name string, context ...string) ED521 {
    ctx := ""
    if len(context) > 0 {
        ctx = context[0]
    }

    switch name {
        case "ED521Ph":
            this.options = &Options{
                Hash:    crypto.Hash(0),
                Context: ctx,
                Scheme:  ed521.ED521Ph,
            }
        case "ED521":
            this.options = &Options{
                Hash:    crypto.Hash(0),
                Context: ctx,
                Scheme:  ed521.ED521,
            }
    }

    return this
}

// With data
func (this ED521) WithData(data []byte) ED521 {
    this.data = data

    return this
}

// With parsedData
func (this ED521) WithParsedData(data []byte) ED521 {
    this.parsedData = data

    return this
}

// With verify
func (this ED521) WithVerify(data bool) ED521 {
    this.verify = data

    return this
}

// With error list
func (this ED521) WithErrors(errs []error) ED521 {
    this.Errors = errs

    return this
}
