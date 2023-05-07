package pkcs8pbe

import(
    "github.com/deatil/go-cryptobin/pkcs/pbes1"
)

// 别名
type (
    PEMCipher = pbes1.PEMCipher
)

var (
    AddCipher = pbes1.AddCipher
    GetCipher = pbes1.GetCipher

    // 帮助函数
    GetCipherFromName   = pbes1.GetCipherFromName
    CheckCipherFromName = pbes1.CheckCipherFromName
)

// 加密方式
var (
    PEMCipherSHA1And3DES    = pbes1.PEMCipherSHA1And3DES
    PEMCipherSHA1And2DES    = pbes1.PEMCipherSHA1And2DES
    PEMCipherSHA1AndRC2_128 = pbes1.PEMCipherSHA1AndRC2_128
    PEMCipherSHA1AndRC2_40  = pbes1.PEMCipherSHA1AndRC2_40
    PEMCipherSHA1AndRC4_128 = pbes1.PEMCipherSHA1AndRC4_128
    PEMCipherSHA1AndRC4_40  = pbes1.PEMCipherSHA1AndRC4_40

    PEMCipherMD2AndDES     = pbes1.PEMCipherMD2AndDES
    PEMCipherMD2AndRC2_64  = pbes1.PEMCipherMD2AndRC2_64
    PEMCipherMD5AndDES     = pbes1.PEMCipherMD5AndDES
    PEMCipherMD5AndRC2_64  = pbes1.PEMCipherMD5AndRC2_64
    PEMCipherSHA1AndDES    = pbes1.PEMCipherSHA1AndDES
    PEMCipherSHA1AndRC2_64 = pbes1.PEMCipherSHA1AndRC2_64
)
