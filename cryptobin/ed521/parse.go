package ed521

import (
    "errors"
    "crypto"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("go-cryptobin/ed521: invalid key: Key must be a PEM encoded PKCS8 key")
    ErrNotEdPrivateKey     = errors.New("go-cryptobin/ed521: key is not a valid ED521 private key")
    ErrNotEdPublicKey      = errors.New("go-cryptobin/ed521: key is not a valid ED521 public key")
)

// 解析私钥
func (this ED521) ParsePrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    if pkey, err := ed521.ParsePrivateKey(block.Bytes); err == nil {
        return pkey, nil
    }

    return nil, ErrNotEdPrivateKey
}

// 解析私钥带密码
func (this ED521) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = pkcs8.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    if pkey, err := ed521.ParsePrivateKey(blockDecrypted); err == nil {
        return pkey, nil
    }

    return nil, ErrNotEdPrivateKey
}

// 解析公钥
func (this ED521) ParsePublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = ed521.ParsePublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    if pkey, ok := parsedKey.(*ed521.PublicKey); ok {
        return pkey, nil
    }

    return nil, ErrNotEdPublicKey
}
