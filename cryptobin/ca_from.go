package cryptobin

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"

    "github.com/tjfoc/gmsm/sm2"
)

// 私钥
func (this CA) FromCsr(csr *x509.Certificate) CA {
    this.csr = csr

    return this
}

// 私钥
// 可用 [*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey]
func (this CA) FromPrivateKey(key any) CA {
    this.privateKey = key

    return this
}

// 公钥
// 可用 [*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey]
func (this CA) FromPublicKey(key any) CA {
    this.publicKey = key

    return this
}

// =======================

// 生成密钥 RSA
// bits = 512 | 1024 | 2048 | 4096
func (this CA) GenerateRsaKey(bits int) CA {
    // 生成私钥
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)

    this.privateKey = privateKey
    this.Error = err

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥 Ecdsa
// 可选 [P521 | P384 | P256 | P224]
func (this CA) GenerateEcdsaKey(curve string) CA {
    var useCurve elliptic.Curve

    switch {
        case curve == "P521":
            useCurve = elliptic.P521()
        case curve == "P384":
            useCurve = elliptic.P384()
        case curve == "P256":
            useCurve = elliptic.P256()
        case curve == "P224":
            useCurve = elliptic.P224()
        default:
            useCurve = elliptic.P256()
    }

    // 生成私钥
    privateKey, err := ecdsa.GenerateKey(useCurve, rand.Reader)

    this.privateKey = privateKey
    this.Error = err

    // 生成公钥
    this.publicKey = &ecdsa.PublicKey{
        Curve: useCurve,
        X: privateKey.X,
        Y: privateKey.Y,
    }

    return this
}

// 生成密钥 EdDSA
func (this CA) GenerateEdDSAKey() CA {
    this.publicKey, this.privateKey, this.Error = ed25519.GenerateKey(rand.Reader)

    return this
}

// 生成密钥 SM2
func (this CA) GenerateSM2Key() CA {
    // 生成私钥
    privateKey, err := sm2.GenerateKey(rand.Reader)

    this.privateKey = privateKey
    this.Error = err

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}
