package sign

import (
    "crypto"

    cryptobin_crypto "github.com/deatil/go-cryptobin/crypto"
)

// 通用加密
func hashSignData(hashType crypto.Hash, data []byte) []byte {
    h := hashType.New()
    h.Write(data)
    hash := h.Sum(nil)

    return hash
}

// 通用加密
func cryptobinHashSignData(hashType cryptobin_crypto.Hash, data []byte) []byte {
    h := hashType.New()
    h.Write(data)
    hash := h.Sum(nil)

    return hash
}

