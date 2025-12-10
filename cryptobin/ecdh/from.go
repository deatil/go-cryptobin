package ecdh

import (
    "io"
    "crypto/rand"
    "crypto/ecdh"

    "github.com/deatil/go-cryptobin/tool/pem"
)

// GenerateKey With Seed
func (this ECDH) GenerateKeyWithSeed(reader io.Reader) ECDH {
    privateKey, err := this.curve.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = privateKey.PublicKey()

    return this
}

// GenerateKey With Seed
func GenerateKeyWithSeed(reader io.Reader, curve string) ECDH {
    return defaultECDH.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// GenerateKey
func (this ECDH) GenerateKey() ECDH {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// GenerateKey
func GenerateKey(curve string) ECDH {
    return defaultECDH.SetCurve(curve).GenerateKey()
}

// ==========

// From PrivateKey bytes
func (this ECDH) FromPrivateKey(key []byte) ECDH {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// From PrivateKey bytes
func FromPrivateKey(key []byte) ECDH {
    return defaultECDH.FromPrivateKey(key)
}

// From PrivateKey bytes With Password
func (this ECDH) FromPrivateKeyWithPassword(key []byte, password string) ECDH {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// From PrivateKey bytes With Password
func FromPrivateKeyWithPassword(key []byte, password string) ECDH {
    return defaultECDH.FromPrivateKeyWithPassword(key, password)
}

// From PublicKey bytes
func (this ECDH) FromPublicKey(key []byte) ECDH {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// From PublicKey bytes
func FromPublicKey(key []byte) ECDH {
    return defaultECDH.FromPublicKey(key)
}

// ==========

// From PrivateKey Der bytes
func (this ECDH) FromPrivateKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// From PublicKey Der bytes
func FromPrivateKeyDer(der []byte) ECDH {
    return defaultECDH.FromPrivateKeyDer(der)
}

// From PublicKey Der bytes
func (this ECDH) FromPublicKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// From PublicKey Der bytes
func FromPublicKeyDer(der []byte) ECDH {
    return defaultECDH.FromPublicKeyDer(der)
}

// ==========

// From ECDH PrivateKey bytes
func (this ECDH) FromECDHPrivateKey(key []byte) ECDH {
    parsedKey, err := this.ParseECDHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// From ECDH PrivateKey bytes
func FromECDHPrivateKey(key []byte) ECDH {
    return defaultECDH.FromECDHPrivateKey(key)
}

// From ECDH PrivateKey bytes With Password
func (this ECDH) FromECDHPrivateKeyWithPassword(key []byte, password string) ECDH {
    parsedKey, err := this.ParseECDHPrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// From ECDH PrivateKey bytes With Password
func FromECDHPrivateKeyWithPassword(key []byte, password string) ECDH {
    return defaultECDH.FromECDHPrivateKeyWithPassword(key, password)
}

// From ECDH PublicKey bytes
func (this ECDH) FromECDHPublicKey(key []byte) ECDH {
    parsedKey, err := this.ParseECDHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// From ECDH PublicKey bytes
func FromECDHPublicKey(key []byte) ECDH {
    return defaultECDH.FromECDHPublicKey(key)
}

// ==========

// From ECDH PrivateKey Der bytes
func (this ECDH) FromECDHPrivateKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParseECDHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// From ECDH PrivateKey Der bytes
func FromECDHPrivateKeyDer(der []byte) ECDH {
    return defaultECDH.FromECDHPrivateKeyDer(der)
}

// From ECDH PublicKey Der bytes
func (this ECDH) FromECDHPublicKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParseECDHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// From ECDH PublicKey Der bytes
func FromECDHPublicKeyDer(der []byte) ECDH {
    return defaultECDH.FromECDHPublicKeyDer(der)
}
