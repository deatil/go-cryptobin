package ed448

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ed448"
)

// GenerateKey With Seed
func (this ED448) GenerateKeyWithSeed(reader io.Reader) ED448 {
    publicKey, privateKey, err := ed448.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this
}

// GenerateKey With Seed
func GenerateKeyWithSeed(reader io.Reader) ED448 {
    return defaultED448.GenerateKeyWithSeed(reader)
}

// GenerateKey
func (this ED448) GenerateKey() ED448 {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// GenerateKey
func GenerateKey() ED448 {
    return defaultED448.GenerateKey()
}

// ==========

// From PrivateKey bytes
func (this ED448) FromPrivateKey(key []byte) ED448 {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed448.PrivateKey)

    return this
}

// From PrivateKey bytes
func FromPrivateKey(key []byte) ED448 {
    return defaultED448.FromPrivateKey(key)
}

// From PrivateKey bytes With Password
func (this ED448) FromPrivateKeyWithPassword(key []byte, password string) ED448 {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed448.PrivateKey)

    return this
}

// From PrivateKey bytes With Password
func FromPrivateKeyWithPassword(key []byte, password string) ED448 {
    return defaultED448.FromPrivateKeyWithPassword(key, password)
}

// From PublicKey bytes
func (this ED448) FromPublicKey(key []byte) ED448 {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed448.PublicKey)

    return this
}

// From PublicKey bytes
func FromPublicKey(key []byte) ED448 {
    return defaultED448.FromPublicKey(key)
}

// ==========

// From PrivateKey Der bytes
func (this ED448) FromPrivateKeyDer(der []byte) ED448 {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(ed448.PrivateKey)

    return this
}

// From PrivateKey Der bytes
func FromPrivateKeyDer(der []byte) ED448 {
    return defaultED448.FromPrivateKeyDer(der)
}

// From PublicKey Der bytes
func (this ED448) FromPublicKeyDer(der []byte) ED448 {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(ed448.PublicKey)

    return this
}

// From PublicKey Der bytes
func FromPublicKeyDer(der []byte) ED448 {
    return defaultED448.FromPublicKeyDer(der)
}

// ==========

// From PrivateKey Seed bytes
func (this ED448) FromPrivateKeySeed(seed []byte) ED448 {
    this.privateKey = ed448.NewKeyFromSeed(seed)

    return this
}

// From PrivateKey Seed bytes
func FromPrivateKeySeed(seed []byte) ED448 {
    return defaultED448.FromPrivateKeySeed(seed)
}

// ==========

// PublicKey hex string
func (this ED448) FromPublicKeyString(keyString string) ED448 {
    k, _ := encoding.HexDecode(keyString)

    this.publicKey = ed448.PublicKey(k)

    return this
}

// PrivateKey hex string
// private-key: 07e4********;
func (this ED448) FromPrivateKeyString(keyString string) ED448 {
    k, _ := encoding.HexDecode(keyString)

    this.privateKey = ed448.PrivateKey(k)

    return this
}

// ==========

// From Bytes
func (this ED448) FromBytes(data []byte) ED448 {
    this.data = data

    return this
}

// From Bytes
func FromBytes(data []byte) ED448 {
    return defaultED448.FromBytes(data)
}

// From String
func (this ED448) FromString(data string) ED448 {
    this.data = []byte(data)

    return this
}

// From String
func FromString(data string) ED448 {
    return defaultED448.FromString(data)
}

// From Base64 String
func (this ED448) FromBase64String(data string) ED448 {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// From Base64 String
func FromBase64String(data string) ED448 {
    return defaultED448.FromBase64String(data)
}

// From Hex String
func (this ED448) FromHexString(data string) ED448 {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// From Hex String
func FromHexString(data string) ED448 {
    return defaultED448.FromHexString(data)
}
