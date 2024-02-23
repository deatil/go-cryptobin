package gost

import (
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
)

var (
    // PublicKey oid
    oidGOSTPublicKey         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
    oidGost2012PublicKey256  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
    oidGost2012PublicKey512  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

    // Digest oid
    oidGost2012Digest256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
    oidGost2012Digest512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
    oidGost94Digest      = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
    oidCryptoProDigestA  = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1}

    oidGostR3410_2001_TestParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 0}

    oidTc26_gost_3410_12_256_paramSetA     = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
    oidGostR3410_2001_CryptoPro_A_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
    oidGostR3410_2001_CryptoPro_B_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
    oidGostR3410_2001_CryptoPro_C_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}

    oidCryptoPro2012Sign256A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
    oidCryptoPro2012Sign512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
    oidCryptoPro2012Sign512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
    oidCryptoPro2012Sign512C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}

    oidTc26_gost_3410_12_512_paramSetA = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
    oidTc26_gost_3410_12_512_paramSetB = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
    oidTc26_gost_3410_12_512_paramSetC = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}

    /* OID for EC DH */
    oidGostR3410_2001_CryptoPro_XchA_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
    oidGostR3410_2001_CryptoPro_XchB_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}
)

func init() {
    AddNamedCurve(CurveIdGostR34102001TestParamSet(), oidGostR3410_2001_TestParamSet)

    AddNamedCurve(CurveIdtc26gost341012256paramSetA(), oidTc26_gost_3410_12_256_paramSetA)
    AddNamedCurve(CurveIdGostR34102001CryptoProAParamSet(), oidGostR3410_2001_CryptoPro_A_ParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProBParamSet(), oidGostR3410_2001_CryptoPro_B_ParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProCParamSet(), oidGostR3410_2001_CryptoPro_C_ParamSet)

    AddNamedCurve(CurveIdtc26gost341012512paramSetA(), oidTc26_gost_3410_12_512_paramSetA)
    AddNamedCurve(CurveIdtc26gost341012512paramSetB(), oidTc26_gost_3410_12_512_paramSetB)
    AddNamedCurve(CurveIdtc26gost341012512paramSetC(), oidTc26_gost_3410_12_512_paramSetC)

    AddNamedCurve(CurveIdGostR34102001CryptoProXchAParamSet(), oidGostR3410_2001_CryptoPro_XchA_ParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProXchBParamSet(), oidGostR3410_2001_CryptoPro_XchB_ParamSet)
}

const gostPrivKeyVersion = 1

// pkcs8 data
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// Key Algo
type keyAlgoParam struct {
    Curve  asn1.ObjectIdentifier
    Digest asn1.ObjectIdentifier `asn1:"optional"`
}

// PublicKey data
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// publicKeyInfo parse
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// Marshal PublicKey
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := OidFromNamedCurve(pub.Curve)
    if !ok {
        return nil, errors.New("gost: unsupported gost curve")
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(keyAlgoParam{
        Curve: oid,
    })
    if err != nil {
        return nil, err
    }

    publicKeyAlgorithm.Algorithm = oidGOSTPublicKey
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return nil, errors.New("gost: invalid gost curve public key")
    }

    publicKeyBytes = Marshal(pub.Curve, pub.X, pub.Y)

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// Parse PublicKey
func ParsePublicKey(derBytes []byte) (pub *PublicKey, err error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return
    } else if len(rest) != 0 {
        err = errors.New("gost: trailing data after ASN.1 of public-key")
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    algo := pki.Algorithm.Algorithm
    params := pki.Algorithm.Parameters
    der := cryptobyte.String(pki.PublicKey.RightAlign())

    if !algo.Equal(oidGOSTPublicKey) &&
        !algo.Equal(oidGost2012PublicKey256) &&
        !algo.Equal(oidGost2012PublicKey512) {
        err = errors.New("gost: unknown public key algorithm")
        return
    }

    var param keyAlgoParam
    if _, err := asn1.Unmarshal(params.FullBytes, &param); err != nil {
        err = errors.New("gost: unknown public key algorithm curve")
        return nil, err
    }

    namedCurve := NamedCurveFromOid(param.Curve)
    if namedCurve == nil {
        err = errors.New("gost: unsupported gost curve")
        return
    }

    x, y := Unmarshal(namedCurve, der)
    if x == nil || y == nil {
        err = errors.New("gost: failed to unmarshal gost curve point")
        return
    }

    pub = &PublicKey{
        Curve: namedCurve,
        X:     x,
        Y:     y,
    }

    return
}

// Marshal PrivateKey
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    oid, ok := OidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("gost: unsupported gost curve")
    }

    // Marshal oid
    oidBytes, err := asn1.Marshal(keyAlgoParam{
        Curve: oid,
    })
    if err != nil {
        return nil, errors.New("gost: failed to marshal algo param: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidGOSTPublicKey,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("invalid elliptic key public key")
    }

    privKey.PrivateKey, err = marshalGostPrivateKeyWithOID(key, oid)
    if err != nil {
        return nil, errors.New("gost: failed to marshal EC private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}

// Parse PrivateKey
func ParsePrivateKey(derBytes []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    algo := privKey.Algo.Algorithm
    if !algo.Equal(oidGOSTPublicKey) &&
        !algo.Equal(oidGost2012PublicKey256) &&
        !algo.Equal(oidGost2012PublicKey512) {
        err = errors.New("gost: unknown private key algorithm")
        return nil, err
    }

    bytes := privKey.Algo.Parameters.FullBytes

    var param keyAlgoParam
    if _, err := asn1.Unmarshal(bytes, &param); err != nil {
        err = errors.New("gost: unknown private key algorithm curve")
        return nil, err
    }

    key, err := parseGostPrivateKey(param.Curve, privKey.PrivateKey)
    if err != nil {
        return nil, errors.New("gost: failed to parse EC private key embedded in PKCS#8: " + err.Error())
    }

    return key, nil
}

func marshalGostPrivateKeyWithOID(key *PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("invalid gost key public key")
    }

    var b cryptobyte.Builder
    b.AddASN1BigInt(key.D)

    privASN1, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    return privASN1, nil
}

func parseGostPrivateKey(namedCurveOID asn1.ObjectIdentifier, der []byte) (key *PrivateKey, err error) {
    var privKey big.Int

    input := cryptobyte.String(der)
    if !input.ReadASN1Integer(&privKey) {
        return nil, errors.New("gost: failed to parse private key")
    }

    curve := NamedCurveFromOid(namedCurveOID)
    if curve == nil {
        return nil, errors.New("gost: unknown gost curve")
    }

    priv, err := NewPrivateKey(curve, privKey.Bytes())
    if err != nil {
        return nil, err
    }

    return priv, nil
}
