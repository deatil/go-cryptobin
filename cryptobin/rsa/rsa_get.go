package rsa

import (
    "crypto/rsa"
)

// 获取 PrivateKey
func (this Rsa) GetPrivateKey() *rsa.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Rsa) GetPublicKey() *rsa.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this Rsa) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Rsa) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this Rsa) GetParedData() []byte {
    return this.paredData
}

// 获取验证后情况
func (this Rsa) GetVeryed() bool {
    return this.veryed
}

// 获取 hash 类型
func (this Rsa) GetSignHash() string {
    return this.signHash
}

// 获取错误
func (this Rsa) GetError() error {
    return this.Error
}
