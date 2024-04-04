package pkcs7

import (
    "github.com/deatil/go-cryptobin/pkcs7/sign"
    "github.com/deatil/go-cryptobin/pkcs7/encrypt"
)

var (
    // 添加签名数据
    NewSignedData = sign.NewSignedData

    // DegenerateCertificate
    DegenerateCertificate = sign.DegenerateCertificate

    // 加密
    Encrypt = encrypt.Encrypt

    // 加密
    EncryptUsingPSK = encrypt.EncryptUsingPSK

    // 解密
    Decrypt = encrypt.Decrypt

    // 解密
    DecryptUsingPSK = encrypt.DecryptUsingPSK
)

type (
    // 额外信息
    SignerInfoConfig = sign.SignerInfoConfig
)
