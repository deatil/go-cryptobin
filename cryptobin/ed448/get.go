package ed448

import (
    "github.com/deatil/go-cryptobin/pubkey/ed448"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// Get PrivateKey
func (this ED448) GetPrivateKey() ed448.PrivateKey {
    return this.privateKey
}

// Get PrivateKeySeed
func (this ED448) GetPrivateKeySeed() []byte {
    return this.privateKey.Seed()
}

// Get PrivateKeySeed
func (this ED448) GetPrivateKeySeedString() string {
    data := this.privateKey.Seed()

    return encoding.HexEncode(data)
}

// get PrivateKey data hex string
func (this ED448) GetPrivateKeyString() string {
    data := this.privateKey

    return encoding.HexEncode([]byte(data))
}

// Get PublicKey
func (this ED448) GetPublicKey() ed448.PublicKey {
    return this.publicKey
}

// get PublicKey data hex string
func (this ED448) GetPublicKeyString() string {
    data := this.publicKey

    return encoding.HexEncode([]byte(data))
}

// Get Options
func (this ED448) GetOptions() *Options {
    return this.options
}

// Get keyData
func (this ED448) GetKeyData() []byte {
    return this.keyData
}

// Get data
func (this ED448) GetData() []byte {
    return this.data
}

// Get parsedData
func (this ED448) GetParsedData() []byte {
    return this.parsedData
}

// Get verify
func (this ED448) GetVerify() bool {
    return this.verify
}

// Get Error list
func (this ED448) GetErrors() []error {
    return this.Errors
}
