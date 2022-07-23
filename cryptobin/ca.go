package cryptobin

import (
    "crypto/x509"
)

/**
 * CA
 *
 * @create 2022-7-22
 * @author deatil
 */
type CA struct {
    // 证书数据
    csr *x509.Certificate

    // 私钥
    privateKey any

    // 公钥
    publicKey any

    // [私钥/公钥/cert]数据
    keyData []byte

    // 错误
    Error error
}
