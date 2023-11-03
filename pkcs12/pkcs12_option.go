package pkcs12

import (
    cryptobin_pbes1 "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    cryptobin_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

type (
    // PBKDF2 配置
    PBKDF2Opts = cryptobin_pbes2.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = cryptobin_pbes2.ScryptOpts

    // KDF 设置接口
    KeyKDFOpts = cryptobin_pbes2.KDFOpts
)

var (
    // 获取 Cipher 类型
    GetPbes1CipherFromName   = cryptobin_pbes1.GetCipherFromName
    // 检测 Cipher 类型
    CheckPbes1CipherFromName = cryptobin_pbes1.CheckCipherFromName

    // 获取 Cipher 类型
    GetPbes2CipherFromName = cryptobin_pbes2.GetCipherFromName
    // 获取 hash 类型
    GetPbes2HashFromName   = cryptobin_pbes2.GetHashFromName
)

// 配置
type Opts struct {
    KeyCipher   Cipher
    KeyKDFOpts  KeyKDFOpts
    CertCipher  Cipher
    CertKDFOpts CertKDFOpts
}

func (this Opts) WithKeyCipher(cipher Cipher) Opts {
    this.KeyCipher = cipher

    return this
}

func (this Opts) WithKeyKDFOpts(opts KeyKDFOpts) Opts {
    this.KeyKDFOpts = opts

    return this
}

func (this Opts) WithCertCipher(cipher Cipher) Opts {
    this.CertCipher = cipher

    return this
}

func (this Opts) WithCertKDFOpts(opts CertKDFOpts) Opts {
    this.CertKDFOpts = opts

    return this
}

// LegacyRC2
var LegacyRC2Opts = Opts{
    KeyCipher:  cryptobin_pbes1.SHA1And3DES,
    CertCipher: CipherSHA1AndRC2_40,
    CertKDFOpts: MacOpts{
        SaltSize: 8,
        IterationCount: 1,
        HMACHash: SHA1,
    },
}

// LegacyDES
var LegacyDESOpts = Opts{
    KeyCipher:  cryptobin_pbes1.SHA1And3DES,
    CertCipher: CipherSHA1And3DES,
    CertKDFOpts: MacOpts{
        SaltSize: 8,
        IterationCount: 1,
        HMACHash: SHA1,
    },
}

// Passwordless
var PasswordlessOpts = Opts{
    KeyCipher:  nil,
    CertCipher: nil,
    CertKDFOpts: nil,
}

// Modern2023
var Modern2023Opts = Opts{
    KeyCipher:  cryptobin_pbes2.AES256CBC,
    KeyKDFOpts: cryptobin_pbes2.PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 2048,
    },
    CertCipher: cryptobin_pbes2.AES256CBC,
    CertKDFOpts: MacOpts{
        SaltSize: 16,
        IterationCount: 2048,
        HMACHash: SHA256,
    },
}

// LegacyOpts
var LegacyOpts = LegacyDESOpts

// ModernOpts
var ModernOpts = Modern2023Opts

// 默认配置
var DefaultOpts = LegacyRC2Opts
