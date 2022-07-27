package cryptobin

import (
    "fmt"
    "errors"
    "math/big"
    "crypto/dsa"
    "crypto/x509/pkix"
    "encoding/asn1"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
    // dsa 公钥 oid
    dsaOidPublicKeyDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)

// dsa Parameters
type dsaAlgorithmParameters struct {
    P, Q, G *big.Int
}

// 私钥 - 包装
type dsaPkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// 公钥 - 包装
type dsaPkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// 公钥信息 - 解析
type dsaPublicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// PKCS8 包装公钥
func (this DSA) MarshalPKCS8PublicKey(pub *dsa.PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    // 创建数据
    paramBytes, err := asn1.Marshal(dsaAlgorithmParameters{
        P: pub.Parameters.P,
        Q: pub.Parameters.Q,
        G: pub.Parameters.G,
    })
    if err != nil {
        return nil, errors.New("dsa: failed to marshal algo param: " + err.Error())
    }

    publicKeyAlgorithm.Algorithm = dsaOidPublicKeyDSA
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    var yInt cryptobyte.Builder
    yInt.AddASN1BigInt(pub.Y)

    publicKeyBytes, err = yInt.Bytes()
    if err != nil {
        return nil, errors.New("dsa: failed to builder PrivateKey: " + err.Error())
    }

    pkix := dsaPkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    ret, _ := asn1.Marshal(pkix)
    return ret, nil
}

// PKCS8 解析公钥
func (this DSA) ParsePKCS8PublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    var pki dsaPublicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        return nil, asn1.SyntaxError{Msg: "trailing data"}
    }

    algoEq := pki.Algorithm.Algorithm.Equal(dsaOidPublicKeyDSA)
    if !algoEq {
        return nil, errors.New("dsa: unknown public key algorithm")
    }

    // 解析
    keyData := &pki

    der := cryptobyte.String(keyData.PublicKey.RightAlign())

    y := new(big.Int)
    if !der.ReadASN1Integer(y) {
        return nil, errors.New("x509: invalid DSA public key")
    }

    pub := &dsa.PublicKey{
        Y: y,
        Parameters: dsa.Parameters{
            P: new(big.Int),
            Q: new(big.Int),
            G: new(big.Int),
        },
    }

    paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
    if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
        !paramsDer.ReadASN1Integer(pub.Parameters.P) ||
        !paramsDer.ReadASN1Integer(pub.Parameters.Q) ||
        !paramsDer.ReadASN1Integer(pub.Parameters.G) {
        return nil, errors.New("x509: invalid DSA parameters")
    }

    if pub.Y.Sign() <= 0 || pub.Parameters.P.Sign() <= 0 ||
        pub.Parameters.Q.Sign() <= 0 || pub.Parameters.G.Sign() <= 0 {
        return nil, errors.New("x509: zero or negative DSA parameter")
    }

    return pub, nil
}

// ====================

// PKCS8 包装私钥
func (this DSA) MarshalPKCS8PrivateKey(key *dsa.PrivateKey) ([]byte, error) {
    var privKey dsaPkcs8

    // 创建数据
    paramBytes, err := asn1.Marshal(dsaAlgorithmParameters{
        P: key.P,
        Q: key.Q,
        G: key.G,
    })
    if err != nil {
        return nil, errors.New("dsa: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  dsaOidPublicKeyDSA,
        Parameters: asn1.RawValue{
            FullBytes: paramBytes,
        },
    }

    var xInt cryptobyte.Builder
    xInt.AddASN1BigInt(key.X)

    builderResult, err := xInt.Bytes()
    if err != nil {
        return nil, errors.New("dsa: failed to builder PrivateKey: " + err.Error())
    }

    privKey.PrivateKey = builderResult

    return asn1.Marshal(privKey)
}

// PKCS8 解析私钥
func (this DSA) ParsePKCS8PrivateKey(derBytes []byte) (key *dsa.PrivateKey, err error) {
    var privKey dsaPkcs8
    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    switch {
        case privKey.Algo.Algorithm.Equal(dsaOidPublicKeyDSA):
            der := cryptobyte.String(string(privKey.PrivateKey))

            x := new(big.Int)
            if !der.ReadASN1Integer(x) {
                return nil, errors.New("x509: invalid DSA public key")
            }

            priv := &dsa.PrivateKey{
                PublicKey: dsa.PublicKey{
                    Parameters: dsa.Parameters{
                        P: new(big.Int),
                        Q: new(big.Int),
                        G: new(big.Int),
                    },
                    Y: new(big.Int),
                },
                X: x,
            }

            paramsDer := cryptobyte.String(privKey.Algo.Parameters.FullBytes)
            if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
                !paramsDer.ReadASN1Integer(priv.PublicKey.Parameters.P) ||
                !paramsDer.ReadASN1Integer(priv.PublicKey.Parameters.Q) ||
                !paramsDer.ReadASN1Integer(priv.PublicKey.Parameters.G) {
                return nil, errors.New("x509: invalid DSA parameters")
            }

            priv.Y = new(big.Int)
            priv.Y.Exp(priv.G, x, priv.P)

            if priv.PublicKey.Y.Sign() <= 0 || priv.PublicKey.Parameters.P.Sign() <= 0 ||
                priv.PublicKey.Parameters.Q.Sign() <= 0 || priv.PublicKey.Parameters.G.Sign() <= 0 {
                return nil, errors.New("x509: zero or negative DSA parameter")
            }

            return priv, nil

        default:
            return nil, fmt.Errorf("dsa: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }
}
