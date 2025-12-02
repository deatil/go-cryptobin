package ed521

import (
    "github.com/deatil/go-cryptobin/pubkey/ed521"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 获取 PrivateKey
func (this ED521) GetPrivateKey() *ed521.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeySeed
func (this ED521) GetPrivateKeySeed() []byte {
    return this.privateKey.Seed()
}

// 获取 PrivateKeySeed
func (this ED521) GetPrivateKeySeedString() string {
    data := this.privateKey.Seed()

    return encoding.HexEncode(data)
}

// get PrivateKey data hex string
func (this ED521) GetPrivateKeyString() string {
    data := this.privateKey.Bytes()

    return encoding.HexEncode(data)
}

// 获取 PublicKey
func (this ED521) GetPublicKey() *ed521.PublicKey {
    return this.publicKey
}

// get PublicKey data hex string
func (this ED521) GetPublicKeyString() string {
    data := ed521.PublicKeyTo(this.publicKey)

    return encoding.HexEncode(data)
}

// 获取 Options
func (this ED521) GetOptions() *Options {
    return this.options
}

// 获取 keyData
func (this ED521) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this ED521) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this ED521) GetParsedData() []byte {
    return this.parsedData
}

// 获取验证后情况
func (this ED521) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this ED521) GetErrors() []error {
    return this.Errors
}
