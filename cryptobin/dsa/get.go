package dsa

import (
    "crypto/dsa"
)

// get PrivateKey
func (this DSA) GetPrivateKey() *dsa.PrivateKey {
    return this.privateKey
}

// get PublicKey
func (this DSA) GetPublicKey() *dsa.PublicKey {
    return this.publicKey
}

// get keyData
func (this DSA) GetKeyData() []byte {
    return this.keyData
}

// get data
func (this DSA) GetData() []byte {
    return this.data
}

// get parsed data
func (this DSA) GetParsedData() []byte {
    return this.parsedData
}

// get hash type
func (this DSA) GetSignHash() HashFunc {
    return this.signHash
}

// get Encoding type
func (this DSA) GetEncoding() EncodingType {
    return this.encoding
}

// get verify
func (this DSA) GetVerify() bool {
    return this.verify
}

// get error list
func (this DSA) GetErrors() []error {
    return this.Errors
}
