package dsa

import (
    "io"
    "crypto/dsa"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// GenerateKey With Seed
// params [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func (this DSA) GenerateKeyWithSeed(paramReader, generateReader io.Reader, ln string) DSA {
    var paramSize dsa.ParameterSizes

    // 算法类型
    switch ln {
        case "L1024N160":
            paramSize = dsa.L1024N160
        case "L2048N224":
            paramSize = dsa.L2048N224
        case "L2048N256":
            paramSize = dsa.L2048N256
        case "L3072N256":
            paramSize = dsa.L3072N256
        default:
            paramSize = dsa.L1024N160
    }

    priv := &dsa.PrivateKey{}
    dsa.GenerateParameters(&priv.Parameters, paramReader, paramSize)
    dsa.GenerateKey(priv, generateReader)

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// GenerateKey With Seed
// params [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func GenerateKeyWithSeed(paramReader, generateReader io.Reader, ln string) DSA {
    return defaultDSA.GenerateKeyWithSeed(paramReader, generateReader, ln)
}

// GenerateKey
// params [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func (this DSA) GenerateKey(ln string) DSA {
    return this.GenerateKeyWithSeed(rand.Reader, rand.Reader, ln)
}

// GenerateKey
// params [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func GenerateKey(ln string) DSA {
    return defaultDSA.GenerateKey(ln)
}

// ==========

// From PrivateKey bytes
func (this DSA) FromPrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err == nil {
        this.privateKey = parsedKey

        return this
    }

    parsedKey, err = this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PrivateKey bytes
func FromPrivateKey(key []byte) DSA {
    return defaultDSA.FromPrivateKey(key)
}

// From PrivateKey bytes With Password
func (this DSA) FromPrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err == nil {
        this.privateKey = parsedKey

        return this
    }

    parsedKey, err = this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PrivateKey bytes With Password
func FromPrivateKeyWithPassword(key []byte, password string) DSA {
    return defaultDSA.FromPrivateKeyWithPassword(key, password)
}

// From PublicKey bytes
func (this DSA) FromPublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err == nil {
        this.publicKey = parsedKey

        return this
    }

    parsedKey, err = this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// From PublicKey bytes
func FromPublicKey(key []byte) DSA {
    return defaultDSA.FromPublicKey(key)
}

// ==========

// From PKCS1 PrivateKey bytes
func (this DSA) FromPKCS1PrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PKCS1 PrivateKey bytes
func FromPKCS1PrivateKey(key []byte) DSA {
    return defaultDSA.FromPKCS1PrivateKey(key)
}

// From PKCS1 PrivateKey bytes With Password
func (this DSA) FromPKCS1PrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PKCS1 PrivateKey bytes With Password
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) DSA {
    return defaultDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// From PKCS1 PublicKey bytes
func (this DSA) FromPKCS1PublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// From PKCS1 PublicKey bytes
func FromPKCS1PublicKey(key []byte) DSA {
    return defaultDSA.FromPKCS1PublicKey(key)
}

// ==========

// From PKCS8 PrivateKey bytes
func (this DSA) FromPKCS8PrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PKCS8 PrivateKey bytes
func FromPKCS8PrivateKey(key []byte) DSA {
    return defaultDSA.FromPKCS8PrivateKey(key)
}

// From PKCS8 PrivateKey bytes With Password
func (this DSA) FromPKCS8PrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PKCS8 PrivateKey bytes With Password
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) DSA {
    return defaultDSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// From PKCS8 PublicKey bytes
func (this DSA) FromPKCS8PublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// From PKCS8 PublicKey bytes
func FromPKCS8PublicKey(key []byte) DSA {
    return defaultDSA.FromPKCS8PublicKey(key)
}

// ==========

// From PKCS1 PrivateKey Der bytes
func (this DSA) FromPKCS1PrivateKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "DSA PRIVATE KEY")

    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PKCS1 PublicKey Der bytes
func (this DSA) FromPKCS1PublicKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "DSA PUBLIC KEY")

    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// From PKCS8 PrivateKey Der bytes
func (this DSA) FromPKCS8PrivateKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// From PKCS8 PublicKey Der bytes
func (this DSA) FromPKCS8PublicKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// From PrivateKey XML bytes
func (this DSA) FromXMLPrivateKey(key []byte) DSA {
    privateKey, err := this.ParsePrivateKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey XML bytes
func FromXMLPrivateKey(key []byte) DSA {
    return defaultDSA.FromXMLPrivateKey(key)
}

// From PublicKey XML bytes
func (this DSA) FromXMLPublicKey(key []byte) DSA {
    publicKey, err := this.ParsePublicKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// From PublicKey XML bytes
func FromXMLPublicKey(key []byte) DSA {
    return defaultDSA.FromXMLPublicKey(key)
}

// ==========

// From Bytes
func (this DSA) FromBytes(data []byte) DSA {
    this.data = data

    return this
}

// From Bytes
func FromBytes(data []byte) DSA {
    return defaultDSA.FromBytes(data)
}

// From String
func (this DSA) FromString(data string) DSA {
    this.data = []byte(data)

    return this
}

// From String
func FromString(data string) DSA {
    return defaultDSA.FromString(data)
}

// From Base64 String
func (this DSA) FromBase64String(data string) DSA {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// From Base64 String
func FromBase64String(data string) DSA {
    return defaultDSA.FromBase64String(data)
}

// From Hex String
func (this DSA) FromHexString(data string) DSA {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// From Hex String
func FromHexString(data string) DSA {
    return defaultDSA.FromHexString(data)
}
