package encrypt

import (
    "errors"
    "crypto"
    "crypto/rand"
    "encoding/asn1"

    "github.com/tjfoc/gmsm/sm2"
)

// key 用 sm2 加密
type KeyEncryptWithSM2 struct {
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeyEncryptWithSM2) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this KeyEncryptWithSM2) Encrypt(plaintext []byte, pkey crypto.PublicKey) ([]byte, error) {
    var pub *sm2.PublicKey
    var ok bool

    if pub, ok = pkey.(*sm2.PublicKey); !ok {
        return nil, errors.New("pkcs7: PublicKey is not sm2 PublicKey")
    }

    return sm2.EncryptAsn1(pub, plaintext, rand.Reader)
}

// 解密
func (this KeyEncryptWithSM2) Decrypt(ciphertext []byte, pkey crypto.PrivateKey) ([]byte, error) {
    var priv *sm2.PrivateKey
    var ok bool

    if priv, ok = pkey.(*sm2.PrivateKey); !ok {
        return nil, errors.New("pkcs7: PrivateKey is not sm2 PrivateKey")
    }

    return sm2.DecryptAsn1(priv, ciphertext)
}
