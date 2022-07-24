package cryptobin

import (
    "errors"
    "math/big"
    "crypto/dsa"
    "crypto/rand"
    "encoding/asn1"
)

type DSASignature struct {
    R, S *big.Int
}

// 私钥签名
func (this DSA) Sign() DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    hash := NewHash().DataHash(this.signHash, this.data)

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hash)
    if err != nil {
        this.Error = err
        return this
    }

    this.paredData, this.Error = asn1.Marshal(DSASignature{r, s})

    return this
}

// 公钥验证
func (this DSA) Very(data []byte) DSA {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    var dsaSign DSASignature
    _, err := asn1.Unmarshal(this.data, &dsaSign)
    if err != nil {
        this.Error = err

        return this
    }

    hash := NewHash().DataHash(this.signHash, data)

    this.veryed = dsa.Verify(this.publicKey, hash, dsaSign.R, dsaSign.S)

    return this
}
