package ecdsa

import (
    "strings"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this Ecdsa) FromPrivateKey(key []byte) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err == nil {
        this.privateKey = privateKey

        return this
    }

    privateKey, err = this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPrivateKey(key []byte) Ecdsa {
    return defaultECDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this Ecdsa) FromPrivateKeyWithPassword(key []byte, password string) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err == nil {
        this.privateKey = privateKey

        return this
    }

    privateKey, err = this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return defaultECDSA.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this Ecdsa) FromPKCS1PrivateKey(key []byte) Ecdsa {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) Ecdsa {
    return defaultECDSA.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this Ecdsa) FromPKCS1PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return defaultECDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this Ecdsa) FromPKCS8PrivateKey(key []byte) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Ecdsa {
    return defaultECDSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this Ecdsa) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return defaultECDSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this Ecdsa) FromPublicKey(key []byte) Ecdsa {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) Ecdsa {
    return defaultECDSA.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this Ecdsa) FromPKCS1PrivateKeyDer(der []byte) Ecdsa {
    key := cryptobin_tool.EncodeDerToPem(der, "EC PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this Ecdsa) FromPKCS8PrivateKeyDer(der []byte) Ecdsa {
    key := cryptobin_tool.EncodeDerToPem(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this Ecdsa) FromPublicKeyDer(der []byte) Ecdsa {
    key := cryptobin_tool.EncodeDerToPem(der, "PUBLIC KEY")

    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}


// ==========

// 生成密钥
func (this Ecdsa) GenerateKey() Ecdsa {
    privateKey, err := ecdsa.GenerateKey(this.curve, rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKey(hash string) Ecdsa {
    return defaultECDSA.SetCurve(hash).GenerateKey()
}

// ==========

// 公钥字符 (hexStringX + hexStringY)
func (this Ecdsa) FromPublicKeyString(keyString string) Ecdsa {
    if len(keyString) == 130 && strings.HasPrefix(keyString, "04") {
        keyString = strings.TrimPrefix(keyString, "04")
    }

    x, _ := new(big.Int).SetString(keyString[:64], 16)
    y, _ := new(big.Int).SetString(keyString[64:], 16)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥 x,y 16进制字符对
// [xString: xHexString, yString: yHexString]
func (this Ecdsa) FromPublicKeyXYString(xString string, yString string) Ecdsa {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 私钥字符，必须先添加公钥 (hexStringD)
func (this Ecdsa) FromPrivateKeyString(keyString string) Ecdsa {
    d, _ := new(big.Int).SetString(keyString[:], 16)

    this.privateKey = &ecdsa.PrivateKey{
        PublicKey: *this.publicKey,
        D:         d,
    }

    return this
}

// ==========

// 公钥字符对
func (this Ecdsa) FromPublicKeyXYBytes(XBytes, YBytes []byte) Ecdsa {
    x := new(big.Int).SetBytes(XBytes)
    y := new(big.Int).SetBytes(YBytes)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 私钥字符，必须先添加公钥
func (this Ecdsa) FromPrivateKeyDBytes(DBytes []byte) Ecdsa {
    d := new(big.Int).SetBytes(DBytes)

    this.privateKey = &ecdsa.PrivateKey{
        PublicKey: *this.publicKey,
        D:         d,
    }

    return this
}

// ==========

// 明文私钥生成私钥结构体
func (this Ecdsa) FromPrivateKeyBytes(priByte []byte) Ecdsa {
    c := this.curve
    k := new(big.Int).SetBytes(priByte)

    priv := new(ecdsa.PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this Ecdsa) FromBytes(data []byte) Ecdsa {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Ecdsa {
    return defaultECDSA.FromBytes(data)
}

// 字符
func (this Ecdsa) FromString(data string) Ecdsa {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Ecdsa {
    return defaultECDSA.FromString(data)
}

// Base64
func (this Ecdsa) FromBase64String(data string) Ecdsa {
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) Ecdsa {
    return defaultECDSA.FromBase64String(data)
}

// Hex
func (this Ecdsa) FromHexString(data string) Ecdsa {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) Ecdsa {
    return defaultECDSA.FromHexString(data)
}
