package ecdsa

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// output key bytes data
func (this ECDSA) ToKeyBytes() []byte {
    return this.keyData
}

// output key string data
func (this ECDSA) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// output bytes data
func (this ECDSA) ToBytes() []byte {
    return this.parsedData
}

// output string data
func (this ECDSA) ToString() string {
    return string(this.parsedData)
}

// output base64 data
func (this ECDSA) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// output hex data
func (this ECDSA) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// output verify data
func (this ECDSA) ToVerify() bool {
    return this.verify
}

// output verify int data
func (this ECDSA) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
