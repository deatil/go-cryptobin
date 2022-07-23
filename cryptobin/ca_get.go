package cryptobin

import (
    "crypto/x509"
)

// 获取 csr
func (this CA) GetCsr() *x509.Certificate {
    return this.csr
}

// 获取 PrivateKey
func (this CA) GetPrivateKey() any {
    return this.privateKey
}

// 获取 publicKey
func (this CA) GetPublicKey() any {
    return this.publicKey
}

// 获取 keyData
func (this CA) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this CA) GetError() error {
    return this.Error
}
