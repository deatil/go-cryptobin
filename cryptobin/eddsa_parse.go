package cryptobin

import (
    "crypto"
    "crypto/x509"
    "crypto/ed25519"
    "encoding/pem"
    "errors"
)

var (
    ErrNotEdPrivateKey = errors.New("key is not a valid Ed25519 private key")
    ErrNotEdPublicKey  = errors.New("key is not a valid Ed25519 public key")
)

// 解析私钥
func (this EdDSA) ParseEdPrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey ed25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
        return nil, ErrNotEdPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this EdDSA) ParseEdPrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var parsedKey any

    var blockDecrypted []byte
    if blockDecrypted, err = DecryptPKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
        return nil, err
    }

    if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey ed25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
        return nil, ErrNotEdPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this EdDSA) ParseEdPublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey ed25519.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PublicKey); !ok {
        return nil, ErrNotEdPublicKey
    }

    return pkey, nil
}
