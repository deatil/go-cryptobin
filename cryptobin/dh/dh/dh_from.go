package dh

import (
    "math/big"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/dhd/dh"
)

// 私钥
func (this Dh) FromPrivateKey(key []byte) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥带密码
func (this Dh) FromPrivateKeyWithPassword(key []byte, password string) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 公钥
func (this Dh) FromPublicKey(key []byte) Dh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}

// 根据私钥 x, y 生成
func (this Dh) FromKeyXYHexString(name string, xString string, yString string) Dh {
    var param dh.GroupID

    switch name {
        case "P1001":
            param = dh.P1001
        case "P1002":
            param = dh.P1002
        case "P1536":
            param = dh.P1536
        case "P2048":
            param = dh.P2048
        case "P3072":
            param = dh.P3072
        case "P4096":
            param = dh.P4096
        case "P6144":
            param = dh.P6144
        case "P8192":
            param = dh.P8192
        default:
            param = dh.P2048
    }

    paramGroup, err := dh.GetMODPGroup(param)
    if err != nil {
        this.Error = err
        return this
    }

    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    parameters := dh.Parameters{
        P: paramGroup.P,
        G: paramGroup.G,
    }

    priv := &dh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y
    priv.PublicKey.Parameters = parameters

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 生成密钥
func (this Dh) GenerateKey(name string) Dh {
    var param dh.GroupID

    switch name {
        case "P1001":
            param = dh.P1001
        case "P1002":
            param = dh.P1002
        case "P1536":
            param = dh.P1536
        case "P2048":
            param = dh.P2048
        case "P3072":
            param = dh.P3072
        case "P4096":
            param = dh.P4096
        case "P6144":
            param = dh.P6144
        case "P8192":
            param = dh.P8192
        default:
            param = dh.P2048
    }

    this.privateKey, this.publicKey, this.Error = dh.GenerateKey(param, rand.Reader)

    return this
}
