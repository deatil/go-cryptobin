package ed521

import (
    "github.com/deatil/go-cryptobin/pubkey/ed521"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// Get PrivateKey
func (this ED521) GetPrivateKey() *ed521.PrivateKey {
    return this.privateKey
}

// Get PrivateKeySeed
func (this ED521) GetPrivateKeySeed() []byte {
    return this.privateKey.Seed()
}

// Get PrivateKeySeed
func (this ED521) GetPrivateKeySeedString() string {
    data := this.privateKey.Seed()

    return encoding.HexEncode(data)
}

// get PrivateKey data hex string
func (this ED521) GetPrivateKeyString() string {
    data := this.privateKey.Bytes()

    return encoding.HexEncode(data)
}

// Get PublicKey
func (this ED521) GetPublicKey() *ed521.PublicKey {
    return this.publicKey
}

// get PublicKey data hex string
func (this ED521) GetPublicKeyString() string {
    data := ed521.PublicKeyTo(this.publicKey)

    return encoding.HexEncode(data)
}

// Get Options
func (this ED521) GetOptions() *Options {
    return this.options
}

// Get keyData
func (this ED521) GetKeyData() []byte {
    return this.keyData
}

// Get data
func (this ED521) GetData() []byte {
    return this.data
}

// Get parsedData
func (this ED521) GetParsedData() []byte {
    return this.parsedData
}

// Get verify
func (this ED521) GetVerify() bool {
    return this.verify
}

// Get Error list
func (this ED521) GetErrors() []error {
    return this.Errors
}
