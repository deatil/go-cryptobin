package ed448

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// output key bytes data
func (this ED448) ToKeyBytes() []byte {
    return this.keyData
}

// output key string data
func (this ED448) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// output bytes data
func (this ED448) ToBytes() []byte {
    return this.parsedData
}

// output string data
func (this ED448) ToString() string {
    return string(this.parsedData)
}

// output base64 data
func (this ED448) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// output hex data
func (this ED448) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// output verify data
func (this ED448) ToVerify() bool {
    return this.verify
}

// output verify int data
func (this ED448) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
