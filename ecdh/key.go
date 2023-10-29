package ecdh

import (
    "fmt"
    "errors"
    "encoding/asn1"
    "crypto/ecdsa"
    "crypto/x509"
    "crypto/x509/pkix"
    crypto_ecdh "crypto/ecdh"

    "golang.org/x/crypto/cryptobyte"
)

var (
    oidPublicKeyX448 = asn1.ObjectIdentifier{1, 3, 101, 111}
)

// 私钥 - 包装
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// 公钥 - 包装
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// 公钥信息 - 解析
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// 包装公钥
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
    if pub.Curve() == X448() {
        var publicKeyBytes []byte
        var publicKeyAlgorithm pkix.AlgorithmIdentifier

        publicKeyBytes = pub.Bytes()
        publicKeyAlgorithm.Algorithm = oidPublicKeyX448

        pkix := pkixPublicKey{
            Algo: publicKeyAlgorithm,
            BitString: asn1.BitString{
                Bytes:     publicKeyBytes,
                BitLength: 8 * len(publicKeyBytes),
            },
        }

        ret, _ := asn1.Marshal(pkix)
        return ret, nil
    } else {
        pubkey, err := ToPublicKey(pub)
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal public key: %v", err)
        }

        public, err := x509.MarshalPKIXPublicKey(pubkey)
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal public key: %v", err)
        }

        return public, nil
    }
}

// 解析公钥
func ParsePublicKey(derBytes []byte) (*PublicKey, error) {
    var pki publicKeyInfo
    if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
        return nil, err
    } else if len(rest) != 0 {
        return nil, errors.New("x509: trailing data after ASN.1 of public-key")
    }

    keyData := &pki

    oid := keyData.Algorithm.Algorithm
    params := keyData.Algorithm.Parameters
    der := cryptobyte.String(keyData.PublicKey.RightAlign())

    switch {
        case oid.Equal(oidPublicKeyX448):
            if len(params.FullBytes) != 0 {
                return nil, errors.New("x509: X25519 key encoded with illegal parameters")
            }

            return X448().NewPublicKey(der)
        default:
            key, err := x509.ParsePKIXPublicKey(derBytes)
            if err != nil {
                return nil, err
            }

            switch k := key.(type) {
                case *ecdsa.PublicKey:
                    newCurve, err := k.ECDH()
                    if err != nil {
                        return nil, err
                    }

                    return FromPublicKey(newCurve)

                case *crypto_ecdh.PublicKey:
                    if k.Curve() == crypto_ecdh.X25519() {
                        return FromPublicKey(k)
                    }
            }

            return nil, errors.New("x509: unknown public key algorithm")
    }

}

// ====================

// 包装私钥
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    if key.Curve() == X448() {
        privKey.Algo = pkix.AlgorithmIdentifier{
            Algorithm: oidPublicKeyX448,
        }
        var err error
        if privKey.PrivateKey, err = asn1.Marshal(key.Bytes()); err != nil {
            return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
        }
    } else {
        prikey, err := ToPrivateKey(key)
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
        }

        private, err := x509.MarshalPKCS8PrivateKey(prikey)
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
        }

        return private, nil
    }

    return asn1.Marshal(privKey)
}

// 解析私钥
func ParsePrivateKey(der []byte) (*PrivateKey, error) {
    var privKey pkcs8
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, err
    }

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeyX448):
            if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
                return nil, errors.New("x509: invalid X448 private key parameters")
            }

            var curvePrivateKey []byte
            if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
                return nil, fmt.Errorf("x509: invalid X448 private key: %v", err)
            }

            return X448().NewPrivateKey(curvePrivateKey)
        default:
            key, err := x509.ParsePKCS8PrivateKey(der)
            if err != nil {
                return nil, err
            }

            switch k := key.(type) {
                case *ecdsa.PrivateKey:
                    newCurve, err := k.ECDH()
                    if err != nil {
                        return nil, err
                    }

                    return FromPrivateKey(newCurve)
                case *crypto_ecdh.PrivateKey:
                    if k.Curve() == crypto_ecdh.X25519() {
                        return FromPrivateKey(k)
                    }
            }

            return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }
}

// ================

// 格式转换
func FromPrivateKey(key *crypto_ecdh.PrivateKey) (*PrivateKey, error) {
    switch key.Curve() {
        case crypto_ecdh.P256():
            return P256().NewPrivateKey(key.Bytes())
        case crypto_ecdh.P384():
            return P384().NewPrivateKey(key.Bytes())
        case crypto_ecdh.P521():
            return P521().NewPrivateKey(key.Bytes())
        case crypto_ecdh.X25519():
            return X25519().NewPrivateKey(key.Bytes())
    }

    return nil, fmt.Errorf("ecdh: PrivateKey is not support")
}

func ToPrivateKey(key *PrivateKey) (*crypto_ecdh.PrivateKey, error) {
    var newCurve crypto_ecdh.Curve

    switch key.Curve() {
        case P256():
            newCurve = crypto_ecdh.P256()
        case P384():
            newCurve = crypto_ecdh.P384()
        case P521():
            newCurve = crypto_ecdh.P521()
        case X25519():
            newCurve = crypto_ecdh.X25519()
        default:
            return nil, fmt.Errorf("ecdh: unknown key type while marshaling PKCS#8: %T", key)
    }

    prikey, err := newCurve.NewPrivateKey(key.Bytes())
    if err != nil {
        return nil, fmt.Errorf("ecdh: failed to marshal private key: %v", err)
    }

    return prikey, nil
}

func FromPublicKey(pub *crypto_ecdh.PublicKey) (*PublicKey, error) {
    switch pub.Curve() {
        case crypto_ecdh.P256():
            return P256().NewPublicKey(pub.Bytes())
        case crypto_ecdh.P384():
            return P384().NewPublicKey(pub.Bytes())
        case crypto_ecdh.P521():
            return P521().NewPublicKey(pub.Bytes())
        case crypto_ecdh.X25519():
            return X25519().NewPublicKey(pub.Bytes())
    }

    return nil, fmt.Errorf("ecdh: PublicKey is not support")
}

func ToPublicKey(pub *PublicKey) (*crypto_ecdh.PublicKey, error) {
    var newCurve crypto_ecdh.Curve

    switch pub.Curve() {
        case P256():
            newCurve = crypto_ecdh.P256()
        case P384():
            newCurve = crypto_ecdh.P384()
        case P521():
            newCurve = crypto_ecdh.P521()
        case X25519():
            newCurve = crypto_ecdh.X25519()
        default:
            return nil, fmt.Errorf("ecdh: unsupported public key type: %T", pub)
    }

    pubkey, err := newCurve.NewPublicKey(pub.Bytes())
    if err != nil {
        return nil, fmt.Errorf("ecdh: failed to marshal public key: %v", err)
    }

    return pubkey, nil
}
