package dsa

import (
    "errors"
    "crypto/dsa"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_dsa "github.com/deatil/go-cryptobin/pubkey/dsa"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("go-cryptobin/dsa: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotDSAPrivateKey    = errors.New("go-cryptobin/dsa: key is not a valid DSA private key")
    ErrNotDSAPublicKey     = errors.New("go-cryptobin/dsa: key is not a valid DSA public key")
)

// Parse PKCS1 PrivateKey From PEM
func (this DSA) ParsePKCS1PrivateKeyFromPEM(key []byte) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *dsa.PrivateKey
    if pkey, err = cryptobin_dsa.ParsePKCS1PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// Parse PKCS1 PrivateKey From PEM With Password
func (this DSA) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = pkcs1.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    // Parse the key
    var pkey *dsa.PrivateKey
    if pkey, err = cryptobin_dsa.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// Parse PKCS1 PublicKey From PEM
func (this DSA) ParsePKCS1PublicKeyFromPEM(key []byte) (*dsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS1PublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *dsa.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*dsa.PublicKey); !ok {
        return nil, ErrNotDSAPublicKey
    }

    return pkey, nil
}

// =============

// Parse PKCS8 PrivateKey From PEM
func (this DSA) ParsePKCS8PrivateKeyFromPEM(key []byte) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *dsa.PrivateKey
    if pkey, err = cryptobin_dsa.ParsePKCS8PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// Parse PKCS8 PrivateKey From PEM With Password
func (this DSA) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*dsa.PrivateKey, error) {
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

    var pkey *dsa.PrivateKey
    if pkey, err = cryptobin_dsa.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// Parse PKCS8 PublicKey From PEM
func (this DSA) ParsePKCS8PublicKeyFromPEM(key []byte) (*dsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS8PublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *dsa.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*dsa.PublicKey); !ok {
        return nil, ErrNotDSAPublicKey
    }

    return pkey, nil
}

// ============

// Parse PrivateKey From XML
func (this DSA) ParsePrivateKeyFromXML(key []byte) (*dsa.PrivateKey, error) {
    return cryptobin_dsa.ParseXMLPrivateKey(key)
}

// Parse PublicKey From XML
func (this DSA) ParsePublicKeyFromXML(key []byte) (*dsa.PublicKey, error) {
    return cryptobin_dsa.ParseXMLPublicKey(key)
}
