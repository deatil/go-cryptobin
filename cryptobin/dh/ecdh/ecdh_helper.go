package ecdh

import (
    cryptobin_ecdh "github.com/deatil/go-cryptobin/dhd/ecdh"
)

// 构造函数
func NewEcdh() Ecdh {
    curve := cryptobin_ecdh.P256()

    return Ecdh{
        curve: curve,
    }
}

// 构造函数
func New() Ecdh {
    return NewEcdh()
}
