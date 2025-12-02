package ed521

import (
    "crypto"
    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

// 设置 PrivateKey
func (this ED521) WithPrivateKey(data *ed521.PrivateKey) ED521 {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ED521) WithPublicKey(data *ed521.PublicKey) ED521 {
    this.publicKey = data

    return this
}

// 设置 options
func (this ED521) WithOptions(op *Options) ED521 {
    this.options = op

    return this
}

// 设置 options
// 可用类型 [ED521Ph | ED521]
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

// 设置 data
func (this ED521) WithData(data []byte) ED521 {
    this.data = data

    return this
}

// 设置 parsedData
func (this ED521) WithParsedData(data []byte) ED521 {
    this.parsedData = data

    return this
}

// 设置 verify
func (this ED521) WithVerify(data bool) ED521 {
    this.verify = data

    return this
}

// 设置错误
func (this ED521) WithErrors(errs []error) ED521 {
    this.Errors = errs

    return this
}
