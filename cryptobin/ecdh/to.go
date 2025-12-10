package ecdh

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// output key bytes data
func (this ECDH) ToKeyBytes() []byte {
    return this.keyData
}

// output key string data
func (this ECDH) ToKeyString() string {
    return string(this.keyData)
}

// =================

// output bytes data
func (this ECDH) ToBytes() []byte {
    return this.secretData
}

// output string data
func (this ECDH) ToString() string {
    return string(this.secretData)
}

// output base64 data
func (this ECDH) ToBase64String() string {
    return encoding.Base64Encode(this.secretData)
}

// output hex data
func (this ECDH) ToHexString() string {
    return encoding.HexEncode(this.secretData)
}
