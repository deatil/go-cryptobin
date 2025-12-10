package dsa

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// output key bytes data
func (this DSA) ToKeyBytes() []byte {
    return this.keyData
}

// output key string data
func (this DSA) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// output bytes data
func (this DSA) ToBytes() []byte {
    return this.parsedData
}

// output string data
func (this DSA) ToString() string {
    return string(this.parsedData)
}

// output base64 data
func (this DSA) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// output hex data
func (this DSA) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// output verify data
func (this DSA) ToVerify() bool {
    return this.verify
}

// output verify int data
func (this DSA) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
