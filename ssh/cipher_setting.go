package ssh

import (
    "crypto/aes"

    "github.com/tjfoc/gmsm/sm4"
)

var (
    SSHAES128CBC = "aes128-cbc"
    SSHAES128CTR = "aes128-ctr"

    SSHAES192CBC = "aes192-cbc"
    SSHAES192CTR = "aes192-ctr"

    SSHAES256CBC = "aes256-cbc"
    SSHAES256CTR = "aes256-ctr"

    SSHSM4CBC = "sm4-cbc"
    SSHSM4CTR = "sm4-ctr"
)

// AES128CBC is the 128-bit key AES cipher in CBC mode.
var AES128CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: SSHAES128CBC,
}
// AES128CTR is the 128-bit key AES cipher in CTR mode.
var AES128CTR = CipherCTR{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: SSHAES128CTR,
}

// AES192CBC is the 192-bit key AES cipher in CBC mode.
var AES192CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: SSHAES192CBC,
}
// AES192CTR is the 192-bit key AES cipher in CTR mode.
var AES192CTR = CipherCTR{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: SSHAES192CTR,
}

// AES256CBC is the 256-bit key AES cipher in CBC mode.
var AES256CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: SSHAES256CBC,
}
// AES256CTR is the 256-bit key AES cipher in CTR mode.
var AES256CTR = CipherCTR{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: SSHAES256CTR,
}

// SM4CBC is the 128-bit SM4 AES cipher in CBC mode.
var SM4CBC = CipherCBC{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: SSHSM4CBC,
}
// SM4CTR is the 128-bit SM4 AES cipher in CTR mode.
var SM4CTR = CipherCTR{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: SSHSM4CTR,
}

func init() {
    AddCipher(SSHAES128CBC, func() Cipher {
        return AES128CBC
    })
    AddCipher(SSHAES128CTR, func() Cipher {
        return AES128CTR
    })

    AddCipher(SSHAES192CBC, func() Cipher {
        return AES192CBC
    })
    AddCipher(SSHAES192CTR, func() Cipher {
        return AES192CTR
    })

    AddCipher(SSHAES256CBC, func() Cipher {
        return AES256CBC
    })
    AddCipher(SSHAES256CTR, func() Cipher {
        return AES256CTR
    })

    AddCipher(SSHSM4CBC, func() Cipher {
        return SM4CBC
    })
    AddCipher(SSHSM4CTR, func() Cipher {
        return SM4CTR
    })
}
