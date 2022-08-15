package sign

import (
    "errors"
    "crypto"
    "crypto/rand"
    "encoding/asn1"

    "github.com/tjfoc/gmsm/sm2"

    cryptobin_crypto "github.com/deatil/go-cryptobin/crypto"
)

// sm2 签名
type KeySignWithSM2 struct {
    hashFunc   cryptobin_crypto.IHash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithSM2) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithSM2) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithSM2) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv *sm2.PrivateKey
    var ok bool

    if priv, ok = pkey.(*sm2.PrivateKey); !ok {
        return nil, nil, errors.New("pkcs7: PrivateKey is not sm2 PrivateKey")
    }

    hashData := cryptobinHashSignData(this.hashFunc.(cryptobin_crypto.Hash), data)

    signData, err := priv.Sign(rand.Reader, hashData, nil)

    return hashData, signData, err
}

// 验证
func (this KeySignWithSM2) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub *sm2.PublicKey
    var ok bool

    if pub, ok = pkey.(*sm2.PublicKey); !ok {
        return false, errors.New("pkcs7: PublicKey is not sm2 PublicKey")
    }

    hashData := cryptobinHashSignData(this.hashFunc.(cryptobin_crypto.Hash), signed)

    return pub.Verify(hashData, signature), nil
}
