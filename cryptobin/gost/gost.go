package gost

import (
    "hash"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/gost"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

/**
 * Gost
 *
 * @create 2024-2-25
 * @author deatil
 */
type Gost struct {
    // 私钥
    privateKey *gost.PrivateKey

    // 公钥
    publicKey *gost.PublicKey

    // 生成类型
    curve *gost.Curve

    // 签名验证类型
    signHash HashFunc

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    parsedData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewGost() Gost {
    return Gost{
        curve:    gost.CurveDefault(),
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Gost {
    return NewGost()
}

var (
    // 默认
    defaultGost = NewGost()
)
