package ed521

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ed521"
)

// GenerateKey
func (this ED521) GenerateKeyWithSeed(reader io.Reader) ED521 {
    privateKey, err := ed521.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// GenerateKey
func GenerateKeyWithSeed(reader io.Reader) ED521 {
    return defaultED521.GenerateKeyWithSeed(reader)
}

// GenerateKey
func (this ED521) GenerateKey() ED521 {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// GenerateKey
func GenerateKey() ED521 {
    return defaultED521.GenerateKey()
}

// ==========

// 私钥
func (this ED521) FromPrivateKey(key []byte) ED521 {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ed521.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) ED521 {
    return defaultED521.FromPrivateKey(key)
}

// 私钥带密码
func (this ED521) FromPrivateKeyWithPassword(key []byte, password string) ED521 {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ed521.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) ED521 {
    return defaultED521.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this ED521) FromPublicKey(key []byte) ED521 {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ed521.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) ED521 {
    return defaultED521.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this ED521) FromPrivateKeyDer(der []byte) ED521 {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ed521.PrivateKey)

    return this
}

// DER 公钥
func (this ED521) FromPublicKeyDer(der []byte) ED521 {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ed521.PublicKey)

    return this
}

// ==========

// 私钥 Seed
func (this ED521) FromPrivateKeySeed(seed []byte) ED521 {
    prikey, err := ed521.NewKeyFromSeed(seed)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = prikey

    return this
}

// 私钥 Seed
func FromPrivateKeySeed(seed []byte) ED521 {
    return defaultED521.FromPrivateKeySeed(seed)
}

// ==========

// PublicKey hex string
func (this ED521) FromPublicKeyString(keyString string) ED521 {
    k, _ := encoding.HexDecode(keyString)

    pubkey, err := ed521.NewPublicKey(k)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = pubkey

    return this
}

// PrivateKey hex string
// private-key: 07e4********;
func (this ED521) FromPrivateKeyString(keyString string) ED521 {
    k, _ := encoding.HexDecode(keyString)

    prikey, err := ed521.NewKeyFromBytes(k)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = prikey

    return this
}

// ==========

// 字节
func (this ED521) FromBytes(data []byte) ED521 {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) ED521 {
    return defaultED521.FromBytes(data)
}

// 字符
func (this ED521) FromString(data string) ED521 {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) ED521 {
    return defaultED521.FromString(data)
}

// Base64
func (this ED521) FromBase64String(data string) ED521 {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) ED521 {
    return defaultED521.FromBase64String(data)
}

// Hex
func (this ED521) FromHexString(data string) ED521 {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) ED521 {
    return defaultED521.FromHexString(data)
}
