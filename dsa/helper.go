package dsa

import (
    "crypto/dsa"
)

// 生成公钥
func MarshalPublicKey(key *dsa.PublicKey) ([]byte, error) {
    return NewDsaPkcs1Key().MarshalPublicKey(key)
}

// 解析公钥
func ParsePublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    return NewDsaPkcs1Key().ParsePublicKey(derBytes)
}

// 包装私钥
func MarshalPrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    return NewDsaPkcs1Key().MarshalPrivateKey(key)
}

// 解析私钥
func ParsePrivateKey(derBytes []byte) (*dsa.PrivateKey, error) {
    return NewDsaPkcs1Key().ParsePrivateKey(derBytes)
}

// ============

// PKCS8 包装公钥
func MarshalPKCS8PublicKey(pub *dsa.PublicKey) ([]byte, error) {
    return NewDsaPkcs8Key().MarshalPKCS8PublicKey(pub)
}

// PKCS8 解析公钥
func ParsePKCS8PublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    return NewDsaPkcs8Key().ParsePKCS8PublicKey(derBytes)
}

// PKCS8 包装私钥
func MarshalPKCS8PrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    return NewDsaPkcs8Key().MarshalPKCS8PrivateKey(key)
}

// PKCS8 解析私钥
func ParsePKCS8PrivateKey(derBytes []byte) (key *dsa.PrivateKey, err error) {
    return NewDsaPkcs8Key().ParsePKCS8PrivateKey(derBytes)
}
