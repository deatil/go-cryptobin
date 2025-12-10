package dsa

import (
    "crypto/dsa"

    "github.com/deatil/go-cryptobin/tool/hash"
)

// Set PrivateKey
func (this DSA) WithPrivateKey(data *dsa.PrivateKey) DSA {
    this.privateKey = data

    return this
}

// Set PublicKey
func (this DSA) WithPublicKey(data *dsa.PublicKey) DSA {
    this.publicKey = data

    return this
}

// Set data
func (this DSA) WithData(data []byte) DSA {
    this.data = data

    return this
}

// Set parsedData
func (this DSA) WithParsedData(data []byte) DSA {
    this.parsedData = data

    return this
}

// Set hash type
func (this DSA) WithSignHash(data HashFunc) DSA {
    this.signHash = data

    return this
}

// Set hash type
// 可用参数可查看 Hash 结构体数据
func (this DSA) SetSignHash(data string) DSA {
    hash, err := hash.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// Set encoding type
func (this DSA) WithEncoding(encoding EncodingType) DSA {
    this.encoding = encoding

    return this
}

// Set ASN1 Encoding
func (this DSA) WithEncodingASN1() DSA {
    return this.WithEncoding(EncodingASN1)
}

// Set Plain Encoding
func (this DSA) WithEncodingBytes() DSA {
    return this.WithEncoding(EncodingBytes)
}

// Set verify
func (this DSA) WithVerify(data bool) DSA {
    this.verify = data

    return this
}

// Set error list
func (this DSA) WithErrors(errs []error) DSA {
    this.Errors = errs

    return this
}
